package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	statsProtocolVersion = 1
	statsUserAgent       = "surface-stats/1"
	statsRequestTimeout  = 12 * time.Second
	statsMaxResponseBody = 16 << 10
)

// StatsSample is signed by the node key. NodeID is the public key itself, so
// the server can verify the payload without a registration step.
type StatsSample struct {
	V               int             `json:"v"`
	NodeID          string          `json:"node_id"`
	Nickname        string          `json:"nickname,omitempty"`
	AdvertiseAddr   string          `json:"advertise_addr,omitempty"`
	PublicIP        string          `json:"public_ip,omitempty"`
	SessionID       string          `json:"session_id"`
	Seq             uint64          `json:"seq"`
	SentAt          string          `json:"sent_at"`
	IntervalSeconds int             `json:"interval_seconds"`
	UptimeSeconds   uint64          `json:"uptime_seconds"`
	Counters        TrafficCounters `json:"counters"`
	Sig             string          `json:"sig"`
}

type statsResponse struct {
	OK         bool   `json:"ok"`
	ObservedIP string `json:"observed_ip"`
	IPSource   string `json:"ip_source"`
	Ranking    string `json:"ranking"`
	Error      string `json:"error"`
}

// StatsReporter periodically publishes cumulative relay counters. Cumulative
// counters make lost reports recoverable: the next accepted sample contains the
// full delta since the previous accepted sample.
type StatsReporter struct {
	node     *Node
	settings *Settings
	logger   *log.Logger
	priv     ed25519.PrivateKey
	nodeID   string

	sessionID string
	started   time.Time
	seq       uint64

	lastObservedIP string

	primaryClient *http.Client
	surfaceClient *http.Client
}

func NewStatsReporter(node *Node, s *Settings, logger *log.Logger, priv ed25519.PrivateKey) *StatsReporter {
	if node != nil && node.stats == nil {
		node.stats = NewTrafficMeter()
	}
	r := &StatsReporter{
		node:      node,
		settings:  s,
		logger:    logger,
		priv:      priv,
		nodeID:    PublicKeyString(priv.Public().(ed25519.PublicKey)),
		sessionID: newStatsSessionID(),
		started:   time.Now(),
	}
	r.primaryClient = &http.Client{
		Timeout: statsRequestTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	transport := &http.Transport{
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext:           r.dialSurface,
	}
	if raw := strings.TrimSpace(s.StatsProxy); raw != "" {
		if proxyURL, err := url.Parse(raw); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			logger.Printf("stats: invalid stats_proxy %q: %v", raw, err)
		}
	}
	r.surfaceClient = &http.Client{Timeout: statsRequestTimeout, Transport: transport}
	return r
}

func newStatsSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (r *StatsReporter) Run(ctx context.Context) {
	if r == nil {
		return
	}
	if !r.settings.StatsEnabled {
		r.logger.Printf("stats: reporting disabled")
		return
	}
	urls := cleanStatsURLs(r.settings.StatsURLs)
	if len(urls) == 0 {
		r.logger.Printf("stats: no stats_urls configured; reporting disabled")
		return
	}
	r.settings.StatsURLs = urls

	interval := time.Duration(r.settings.StatsIntervalSeconds) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	r.logger.Printf("stats: reporting every %s to %s", interval, strings.Join(urls, ", "))

	// Register immediately, then send on every tick. The first sample only
	// establishes the server-side baseline.
	if err := r.send(ctx); err != nil {
		r.logger.Printf("stats: initial report failed: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := r.send(flushCtx); err != nil {
				r.logger.Printf("stats: final report failed: %v", err)
			}
			cancel()
			r.primaryClient.CloseIdleConnections()
			r.surfaceClient.CloseIdleConnections()
			return
		case <-ticker.C:
			if err := r.send(ctx); err != nil {
				r.logger.Printf("stats: report failed: %v", err)
			}
		}
	}
}

func (r *StatsReporter) send(ctx context.Context) error {
	r.seq++
	counters := TrafficCounters{}
	if r.node != nil {
		counters = r.node.stats.Snapshot()
	}
	sample := StatsSample{
		V:               statsProtocolVersion,
		NodeID:          r.nodeID,
		Nickname:        sanitizeNickname(r.settings.StatsNickname),
		AdvertiseAddr:   strings.TrimSpace(r.settings.AdvertiseAddr),
		PublicIP:        r.publicIP(),
		SessionID:       r.sessionID,
		Seq:             r.seq,
		SentAt:          time.Now().UTC().Format(time.RFC3339Nano),
		IntervalSeconds: r.settings.StatsIntervalSeconds,
		UptimeSeconds:   uint64(time.Since(r.started).Seconds()),
		Counters:        counters,
	}
	if err := signStatsSample(r.priv, &sample); err != nil {
		return err
	}
	body, err := json.Marshal(&sample)
	if err != nil {
		return err
	}

	var failures []string
	for _, raw := range r.settings.StatsURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			failures = append(failures, fmt.Sprintf("%s: invalid URL", raw))
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			failures = append(failures, fmt.Sprintf("%s: unsupported scheme", raw))
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", u.Host, err))
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", statsUserAgent)

		client := r.primaryClient
		if IsSurfaceName(u.Hostname()) {
			client = r.surfaceClient
		}
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", u.Host, err))
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, statsMaxResponseBody))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := strings.TrimSpace(string(data))
			if msg == "" {
				msg = resp.Status
			}
			failures = append(failures, fmt.Sprintf("%s: %s", u.Host, msg))
			continue
		}
		var out statsResponse
		if json.Unmarshal(data, &out) == nil && out.ObservedIP != "" {
			r.lastObservedIP = out.ObservedIP
		}
		return nil
	}
	if len(failures) == 0 {
		return errors.New("no stats endpoints available")
	}
	return errors.New(strings.Join(failures, "; "))
}

func (r *StatsReporter) publicIP() string {
	if r.lastObservedIP != "" {
		return r.lastObservedIP
	}
	if host := hostFromAdvertise(r.settings.AdvertiseAddr); host != "" && net.ParseIP(host) != nil {
		return host
	}
	return ""
}

func (r *StatsReporter) dialSurface(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !IsSurfaceName(host) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("stats: invalid surface port %q", portStr)
	}
	if r.node == nil {
		return nil, errors.New("stats: surface fallback requires a running node")
	}

	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := r.node.DialSurfaceE2E(host, port)
		done <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			if res := <-done; res.conn != nil {
				res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-done:
		return res.conn, res.err
	}
}

func signStatsSample(priv ed25519.PrivateKey, sample *StatsSample) error {
	sample.Sig = ""
	raw, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	sample.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func cleanStatsURLs(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func hostFromAdvertise(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func sanitizeNickname(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if b.Len() > 0 {
				b.WriteByte('-')
			}
			continue
		}
		if r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-._")
	runes := []rune(out)
	if len(runes) > 24 {
		out = string(runes[:24])
	}
	if len([]rune(out)) < 3 {
		return ""
	}
	return out
}
