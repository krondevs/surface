package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	connNode  byte = 3
	connPeers byte = 4
)

const (
	peerProtocolVersion = 1
	peerDomain          = "surface-peer-v1"
	peerFrameMax        = 64 * 1024
	peerListMax         = 200
	peerDBMax           = 5000
	peerTTL             = 7 * 24 * time.Hour
	peerTimestampSkew   = 5 * time.Minute
	peerConnectTimeout  = 15 * time.Second
	peerIOTimeout       = 10 * time.Second
	peerAnnounceTimeout = 30 * time.Second
)

type PeerInfo struct {
	PublicKey string    `json:"public_key"`
	Address   string    `json:"address"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Source    string    `json:"source,omitempty"`
}

type peerEnvelope struct {
	Version int    `json:"v"`
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

type announceMessage struct {
	Type         string   `json:"type"`
	PublicKey    string   `json:"public_key"`
	Addresses    []string `json:"addresses,omitempty"`
	Port         int      `json:"port,omitempty"`
	Timestamp    int64    `json:"timestamp"`
	Nonce        string   `json:"nonce"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type challengeMessage struct {
	Type      string `json:"type"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

type challengeResponseMessage struct {
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address,omitempty"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

type peersRequestMessage struct {
	Type      string `json:"type"`
	Limit     int    `json:"limit,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type peersResponseMessage struct {
	Type          string     `json:"type"`
	NodePublicKey string     `json:"node_public_key"`
	Timestamp     int64      `json:"timestamp"`
	Peers         []PeerInfo `json:"peers"`
}

func peerSignedBytes(kind string, payload []byte) []byte {
	prefix := peerDomain + "|" + kind + "|"
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

func writePeerEnvelope(w io.Writer, priv ed25519.PrivateKey, kind string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, peerSignedBytes(kind, raw))
	return writePeerFrame(w, peerEnvelope{
		Version: peerProtocolVersion,
		Payload: raw,
		Sig:     sig,
	})
}

func writePeerFrame(w io.Writer, env peerEnvelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > peerFrameMax {
		return errors.New("peer frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readPeerFrame(r io.Reader) (peerEnvelope, error) {
	var env peerEnvelope
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return env, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > peerFrameMax {
		return env, errors.New("invalid peer frame size")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return env, err
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, err
	}
	if env.Version != peerProtocolVersion {
		return env, fmt.Errorf("unsupported peer protocol version %d", env.Version)
	}
	return env, nil
}

func verifyPeerEnvelope(kind string, env peerEnvelope, pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid peer public key")
	}
	if env.Version != peerProtocolVersion {
		return nil, fmt.Errorf("unsupported peer protocol version %d", env.Version)
	}
	if !ed25519.Verify(pub, peerSignedBytes(kind, env.Payload), env.Sig) {
		return nil, errors.New("invalid peer signature")
	}
	return env.Payload, nil
}

func decodePeerPayload[T any](raw []byte, out *T) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid peer payload: %w", err)
	}
	return nil
}

func randomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func unixNowValid(ts int64) bool {
	if ts == 0 {
		return false
	}
	delta := time.Since(time.Unix(ts, 0))
	if delta < 0 {
		delta = -delta
	}
	return delta <= peerTimestampSkew
}

func normalizeSeedAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port in %q", addr)
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("invalid host in %q", addr)
	}
	return net.JoinHostPort(strings.ToLower(strings.Trim(host, "[]")), strconv.Itoa(port)), nil
}

func normalizePeerAddr(addr string, allowPrivate bool) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("empty peer address")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port in %q", addr)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", fmt.Errorf("peer address %q must use a literal IP", addr)
	}
	if !allowPrivate && !isPublicPeerIP(ip) {
		return "", fmt.Errorf("peer address %q is not public", addr)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func isPublicPeerIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// Carrier-grade NAT 100.64.0.0/10.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}

func remoteIP(conn net.Conn) net.IP {
	if conn == nil || conn.RemoteAddr() == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func tunnelPort(listen string) int {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 9253
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return 9253
	}
	return port
}

func peerAddressFromConn(conn net.Conn, port int) (string, error) {
	ip := remoteIP(conn)
	if ip == nil {
		return "", errors.New("cannot determine peer source IP")
	}
	if port <= 0 || port > 65535 {
		return "", errors.New("invalid peer port")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

type ipRateLimiter struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
}

func newIPRateLimiter(interval time.Duration) *ipRateLimiter {
	return &ipRateLimiter{last: map[string]time.Time{}, interval: interval}
}

func (l *ipRateLimiter) Allow(ip string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.last) > 2048 {
		for key, ts := range l.last {
			if now.Sub(ts) > l.interval*4 {
				delete(l.last, key)
			}
		}
	}
	if ts, ok := l.last[ip]; ok && now.Sub(ts) < l.interval {
		return false
	}
	l.last[ip] = now
	return true
}

func publicKeyOrEmpty(pub ed25519.PublicKey) string {
	if len(pub) == 0 {
		return ""
	}
	return PublicKeyString(pub)
}
