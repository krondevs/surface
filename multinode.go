package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	strategyRoundRobin = "round_robin"
	strategyLatency    = "latency"
	strategyRandom     = "random"
)

var errNoNodesAvailable = errors.New("no nodes available")

// nodePool represents a connection to a single node, managing its yamux session.
type nodePool struct {
	addr string
	mu   sync.RWMutex
	mux  *yamux.Session
	rtt  time.Duration
	err  error
}

func (n *nodePool) setSession(mux *yamux.Session, rtt time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mux = mux
	n.rtt = rtt
	n.err = nil
}

func (n *nodePool) clearSession(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mux = nil
	n.err = err
}

func (n *nodePool) snapshot() (*yamux.Session, time.Duration, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.mux, n.rtt, n.err
}

// MultiNodeDialer manages connections to multiple nodes and implements TargetDialer.
// It maintains persistent connections to each node and selects among them based on
// the configured strategy (round_robin, latency, or random).
type MultiNodeDialer struct {
	settings *Settings
	priv     ed25519.PrivateKey
	aliases  map[string]string
	logger   *log.Logger

	mu       sync.RWMutex
	nodes    map[string]*nodePool
	ctx      context.Context
	stopped  bool
	wg       sync.WaitGroup
	maxNodes int
	strategy string
	rr       uint64 // atomic counter for round-robin
}

// NewMultiNodeDialer creates a dialer that connects to all configured nodes.
func NewMultiNodeDialer(s *Settings, priv ed25519.PrivateKey, logger *log.Logger) *MultiNodeDialer {
	m := &MultiNodeDialer{
		settings: s,
		priv:     priv,
		aliases:  s.Aliases,
		logger:   logger,
		nodes:    map[string]*nodePool{},
		maxNodes: s.PeerMax,
		strategy: s.effectiveNodeStrategy(),
	}
	if m.maxNodes <= 0 {
		m.maxNodes = 64
	}
	for _, addr := range s.effectiveNodeAddrs() {
		m.addNodeLocked(addr)
	}
	return m
}

func normalizeNodeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

func (m *MultiNodeDialer) addNodeLocked(addr string) *nodePool {
	addr = normalizeNodeAddr(addr)
	if addr == "" {
		return nil
	}
	if node, ok := m.nodes[addr]; ok {
		return node
	}
	if len(m.nodes) >= m.maxNodes {
		return nil
	}
	node := &nodePool{addr: addr}
	m.nodes[addr] = node
	return node
}

// AddInitialPeer registers a peer before Run starts.
func (m *MultiNodeDialer) AddInitialPeer(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addNodeLocked(addr)
}

// AddPeer registers a dynamically discovered peer and starts maintaining it.
func (m *MultiNodeDialer) AddPeer(addr string) bool {
	addr = normalizeNodeAddr(addr)
	m.mu.Lock()
	if _, ok := m.nodes[addr]; ok {
		m.mu.Unlock()
		return false
	}
	if len(m.nodes) >= m.maxNodes {
		m.mu.Unlock()
		return false
	}
	node := &nodePool{addr: addr}
	m.nodes[addr] = node
	ctx := m.ctx
	if m.stopped || ctx == nil || ctx.Err() != nil {
		m.mu.Unlock()
		return false
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		m.maintain(ctx, node)
	}()
	m.logger.Printf("discovered peer %s", node.addr)
	return true
}

func (m *MultiNodeDialer) startNode(ctx context.Context, node *nodePool) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.maintain(ctx, node)
	}()
}

// Run maintains connections to all nodes concurrently. It blocks until ctx is canceled.
func (m *MultiNodeDialer) Run(ctx context.Context) {
	m.mu.Lock()
	if m.ctx != nil {
		m.mu.Unlock()
		return
	}
	m.ctx = ctx
	nodes := make([]*nodePool, 0, len(m.nodes))
	for _, node := range m.nodes {
		nodes = append(nodes, node)
	}
	m.mu.Unlock()
	for _, node := range nodes {
		m.startNode(ctx, node)
	}
	<-ctx.Done()
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	m.wg.Wait()
}

// maintain keeps a single node connection alive, reconnecting on failure.
func (m *MultiNodeDialer) maintain(ctx context.Context, n *nodePool) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		conn, err := dialTLSAddr(m.settings, n.addr)
		if err == nil {
			err = peerHandshake(conn, m.priv, connRequest, handshakeTimeout)
		}
		var mux *yamux.Session
		if err == nil {
			mux, err = yamux.Client(conn, yamuxConfig())
		}
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			n.clearSession(err)
			m.logger.Printf("node %s unavailable: %v", n.addr, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			continue
		}

		rtt := time.Since(start)
		n.setSession(mux, rtt)
		m.logger.Printf("connected to node %s (rtt=%s)", n.addr, rtt.Round(time.Millisecond))
		backoff = time.Second

		select {
		case <-ctx.Done():
			mux.Close()
			return
		case <-mux.CloseChan():
			n.clearSession(errors.New("session closed"))
			m.logger.Printf("node %s disconnected", n.addr)
		}
	}
}

// DialTarget implements TargetDialer. It selects a node based on the configured
// strategy and opens a stream to the target. On failure, it tries the next node.
func (m *MultiNodeDialer) DialTarget(host string, port int) (net.Conn, error) {
	target := NormalizeHost(host)
	if mapped, ok := m.aliases[target]; ok {
		target = NormalizeHost(mapped)
	}

	candidates := m.candidates()
	if len(candidates) == 0 {
		return nil, errNoNodesAvailable
	}

	var lastErr error
	for _, node := range candidates {
		mux, _, _ := node.snapshot()
		if mux == nil {
			continue
		}
		stream, err := mux.Open()
		if err != nil {
			lastErr = err
			continue
		}
		if err := writeRequestHeaderV2(stream, target, port); err != nil {
			stream.Close()
			lastErr = err
			continue
		}
		status, e2e, pub, version, err := readResponseHeader(stream)
		if err != nil {
			stream.Close()
			lastErr = err
			continue
		}
		if status != respOK {
			stream.Close()
			if status == respExitUnavailable {
				if IsOnionName(target) {
					lastErr = fmt.Errorf("node %s: onion routing unavailable (Tor not configured or unreachable)", node.addr)
				} else {
					lastErr = fmt.Errorf("node %s: exit unavailable", node.addr)
				}
			} else {
				lastErr = fmt.Errorf("node %s: request failed with status %d", node.addr, status)
			}
			continue
		}
		if !IsSurfaceName(target) {
			return stream, nil
		}
		// Zero-trust: a .surface stream must be end-to-end encrypted.
		if !e2e {
			stream.Close()
			lastErr = fmt.Errorf("node %s did not offer end-to-end encryption for %s", node.addr, target)
			continue
		}
		if version != e2eVersion1 {
			stream.Close()
			lastErr = fmt.Errorf("node %s offered unsupported e2e version %d", node.addr, version)
			continue
		}
		if DeriveName(pub) != target {
			stream.Close()
			lastErr = fmt.Errorf("agent key does not match service name %s", target)
			continue
		}
		secure, err := dialE2E(stream, pub, target, port)
		if err != nil {
			stream.Close()
			lastErr = err
			continue
		}
		return secure, nil
	}

	if lastErr == nil {
		lastErr = errNoNodesAvailable
	}
	return nil, lastErr
}

// candidates returns healthy nodes ordered by the configured strategy.
func (m *MultiNodeDialer) candidates() []*nodePool {
	m.mu.RLock()
	healthy := make([]*nodePool, 0, len(m.nodes))
	for _, node := range m.nodes {
		mux, _, _ := node.snapshot()
		if mux != nil {
			healthy = append(healthy, node)
		}
	}
	m.mu.RUnlock()
	if len(healthy) == 0 {
		return nil
	}

	switch m.strategy {
	case strategyLatency:
		sort.SliceStable(healthy, func(i, j int) bool {
			_, rttI, _ := healthy[i].snapshot()
			_, rttJ, _ := healthy[j].snapshot()
			return rttI < rttJ
		})
	case strategyRandom:
		rand.Shuffle(len(healthy), func(i, j int) {
			healthy[i], healthy[j] = healthy[j], healthy[i]
		})
	default: // round_robin
		if len(healthy) > 1 {
			start := int(atomic.AddUint64(&m.rr, 1)-1) % len(healthy)
			healthy = append(healthy[start:], healthy[:start]...)
		}
	}
	return healthy
}
