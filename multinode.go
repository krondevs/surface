package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"math/rand"
	"net"
	"sort"
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

	nodes    []*nodePool
	strategy string
	rr       uint64 // atomic counter for round-robin
}

// NewMultiNodeDialer creates a dialer that connects to all configured nodes.
func NewMultiNodeDialer(s *Settings, priv ed25519.PrivateKey, logger *log.Logger) *MultiNodeDialer {
	addrs := s.effectiveNodeAddrs()
	nodes := make([]*nodePool, 0, len(addrs))
	for _, addr := range addrs {
		nodes = append(nodes, &nodePool{addr: addr})
	}
	return &MultiNodeDialer{
		settings: s,
		priv:     priv,
		aliases:  s.Aliases,
		logger:   logger,
		nodes:    nodes,
		strategy: s.effectiveNodeStrategy(),
	}
}

// Run maintains connections to all nodes concurrently. It blocks until ctx is canceled.
func (m *MultiNodeDialer) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, node := range m.nodes {
		wg.Add(1)
		go func(n *nodePool) {
			defer wg.Done()
			m.maintain(ctx, n)
		}(node)
	}
	wg.Wait()
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
		if err := writeRequestHeader(stream, target, port); err != nil {
			stream.Close()
			lastErr = err
			continue
		}
		return stream, nil
	}

	if lastErr == nil {
		lastErr = errNoNodesAvailable
	}
	return nil, lastErr
}

// candidates returns healthy nodes ordered by the configured strategy.
func (m *MultiNodeDialer) candidates() []*nodePool {
	healthy := make([]*nodePool, 0, len(m.nodes))
	for _, node := range m.nodes {
		mux, _, _ := node.snapshot()
		if mux != nil {
			healthy = append(healthy, node)
		}
	}
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
