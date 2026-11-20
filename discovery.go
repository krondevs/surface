package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// PeerManager runs on a node: it announces itself to seeds and known peers,
// verifies announcements with a callback, stores verified peers and answers
// peer-list requests from clients and agents.
type PeerManager struct {
	settings  *Settings
	registry  *Registry
	identity  ed25519.PrivateKey
	publicKey string
	logger    *log.Logger

	peersLimiter *ipRateLimiter
	nodesLimiter *ipRateLimiter

	knownMu   sync.Mutex
	knownKeys map[string]string
}

func NewPeerManager(s *Settings, registry *Registry, identity ed25519.PrivateKey, logger *log.Logger) *PeerManager {
	return &PeerManager{
		settings:     s,
		registry:     registry,
		identity:     identity,
		publicKey:    PublicKeyString(identity.Public().(ed25519.PublicKey)),
		logger:       logger,
		peersLimiter: newIPRateLimiter(20 * time.Second),
		nodesLimiter: newIPRateLimiter(30 * time.Second),
		knownKeys:    map[string]string{},
	}
}

func (m *PeerManager) Run(ctx context.Context) {
	if m == nil || !m.settings.PeerDiscovery {
		return
	}
	interval := time.Duration(m.settings.PeerRefreshSeconds) * time.Second
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	timer := time.NewTimer(2 * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
	}
	for {
		m.gossip(ctx)
		jitter := time.Duration(rand.Int63n(int64(interval/5) + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval + jitter):
		}
	}
}

func (m *PeerManager) gossip(ctx context.Context) {
	announced := map[string]bool{}
	for _, addr := range m.settings.effectiveSeedNodes() {
		if addr == "" || announced[addr] {
			continue
		}
		announced[addr] = true
		if err := m.announceTo(ctx, addr, "seed"); err != nil {
			m.logger.Printf("peer announce to seed %s failed: %v", addr, err)
		}
	}

	peers, err := m.registry.ListPeers(20, true)
	if err != nil {
		m.logger.Printf("peer list: %v", err)
	} else {
		rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		fanout := 0
		for _, peer := range peers {
			if fanout >= 3 {
				break
			}
			if peer.PublicKey == m.publicKey || announced[peer.Address] {
				continue
			}
			announced[peer.Address] = true
			fanout++
			if err := m.announceTo(ctx, peer.Address, "gossip"); err != nil {
				m.logger.Printf("peer announce to %s failed: %v", peer.Address, err)
			}
		}
	}

	if n, err := m.registry.ExpirePeers(time.Now()); err == nil && n > 0 {
		m.logger.Printf("expired %d peer(s)", n)
	}
}

func (m *PeerManager) announceTo(ctx context.Context, addr, source string) error {
	conn, err := dialTLSAddr(m.settings, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(peerConnectTimeout + peerIOTimeout))
	}
	if err := peerHandshake(conn, m.identity, connNode, handshakeTimeout); err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(peerAnnounceTimeout))
	defer conn.SetDeadline(time.Time{})

	msg := announceMessage{
		Type:         "announce",
		PublicKey:    m.publicKey,
		Timestamp:    time.Now().Unix(),
		Nonce:        randomNonce(),
		Capabilities: []string{"node", "peers-v1"},
	}
	if m.settings.AdvertiseAddr != "" {
		msg.Addresses = []string{m.settings.AdvertiseAddr}
	} else {
		msg.Port = tunnelPort(m.settings.TunnelListen)
	}
	if err := writePeerEnvelope(conn, m.identity, "announce", msg); err != nil {
		return err
	}

	env, err := readPeerFrame(conn)
	if err != nil {
		return err
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(env.Payload, &head); err != nil {
		return err
	}
	if head.Type != "peers" {
		return nil
	}
	var response peersResponseMessage
	if err := json.Unmarshal(env.Payload, &response); err != nil {
		return err
	}
	nodePub, err := ParsePublicKey(response.NodePublicKey)
	if err != nil {
		return err
	}
	if _, err := verifyPeerEnvelope("peers", env, nodePub); err != nil {
		return err
	}
	if !unixNowValid(response.Timestamp) {
		return nil
	}
	if !m.rememberNodeKey(addr, response.NodePublicKey) {
		return nil
	}
	m.mergePeers(ctx, response.Peers, source)
	return nil
}

func (m *PeerManager) mergePeers(ctx context.Context, peers []PeerInfo, source string) {
	verified := 0
	for _, peer := range peers {
		if verified >= 5 {
			return
		}
		if peer.PublicKey == m.publicKey || peer.Address == m.settings.AdvertiseAddr {
			continue
		}
		pub, err := ParsePublicKey(peer.PublicKey)
		if err != nil {
			continue
		}
		addr, err := normalizePeerAddr(peer.Address, m.settings.PeerAllowPrivate)
		if err != nil {
			continue
		}
		if existing, err := m.registry.FindPeer(peer.PublicKey); err == nil {
			if existing.Status == peerStatusVerified && existing.ExpiresAt.After(time.Now()) {
				continue
			}
		}
		verified++
		if err := m.verifyAndStore(ctx, pub, addr, source); err != nil {
			m.logger.Printf("peer callback %s (%s) failed: %v", peer.PublicKey, addr, err)
			m.registry.MarkPeerFailure(peer.PublicKey)
		}
	}
}

func (m *PeerManager) verifyAndStore(ctx context.Context, pub ed25519.PublicKey, addr, source string) error {
	key := PublicKeyString(pub)
	if key == m.publicKey {
		return nil
	}
	if _, err := m.registry.FindPeer(key); err != nil {
		if count, countErr := m.registry.CountPeers(false); countErr == nil && count >= peerDBMax {
			return errPeerStoreFull
		}
	}
	if err := m.verifyCallback(ctx, pub, addr); err != nil {
		return err
	}
	now := time.Now()
	err := m.registry.UpsertPeer(NodePeer{
		PublicKey:  PublicKeyString(pub),
		Address:    addr,
		Status:     peerStatusVerified,
		Source:     source,
		FirstSeen:  now,
		LastSeen:   now,
		LastVerify: now,
		ExpiresAt:  now.Add(peerTTL),
	})
	if err == nil {
		m.logger.Printf("peer verified %s at %s", PublicKeyString(pub), addr)
	}
	return err
}

func (m *PeerManager) verifyCallback(ctx context.Context, pub ed25519.PublicKey, addr string) error {
	conn, err := dialTLSAddr(m.settings, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(peerConnectTimeout + peerIOTimeout))
	}
	if err := peerHandshake(conn, m.identity, connNode, handshakeTimeout); err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(peerIOTimeout))
	defer conn.SetDeadline(time.Time{})

	nonce := randomNonce()
	if err := writePeerEnvelope(conn, m.identity, "challenge", challengeMessage{
		Type:      "challenge",
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}); err != nil {
		return err
	}
	env, err := readPeerFrame(conn)
	if err != nil {
		return err
	}
	var response challengeResponseMessage
	if err := json.Unmarshal(env.Payload, &response); err != nil {
		return err
	}
	if response.Type != "challenge_response" {
		return errUnexpectedPeerMessage
	}
	if _, err := verifyPeerEnvelope("challenge_response", env, pub); err != nil {
		return err
	}
	if response.PublicKey != PublicKeyString(pub) {
		return errPeerKeyMismatch
	}
	if response.Nonce != nonce {
		return errPeerChallengeMismatch
	}
	if !unixNowValid(response.Timestamp) {
		return errPeerTimestamp
	}
	return nil
}

func (m *PeerManager) rememberNodeKey(addr, key string) bool {
	m.knownMu.Lock()
	defer m.knownMu.Unlock()
	if existing, ok := m.knownKeys[addr]; ok && existing != key {
		m.logger.Printf("peer %s changed node key (%s -> %s); ignoring", addr, existing, key)
		return false
	}
	m.knownKeys[addr] = key
	return true
}

func (m *PeerManager) HandleNodeConn(conn net.Conn, peerPub ed25519.PublicKey) {
	if !m.nodesLimiter.Allow(ipString(remoteIP(conn)) + "|" + publicKeyOrEmpty(peerPub)) {
		return
	}
	conn.SetDeadline(time.Now().Add(peerAnnounceTimeout))
	defer conn.SetDeadline(time.Time{})

	env, err := readPeerFrame(conn)
	if err != nil {
		return
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(env.Payload, &head); err != nil {
		return
	}
	switch head.Type {
	case "announce":
		m.handleAnnounce(conn, env, peerPub)
	case "challenge":
		m.handleChallenge(conn, env, peerPub)
	default:
		return
	}
}

func (m *PeerManager) handleAnnounce(conn net.Conn, env peerEnvelope, peerPub ed25519.PublicKey) {
	raw, err := verifyPeerEnvelope("announce", env, peerPub)
	if err != nil {
		m.logger.Printf("peer announce from %s rejected: %v", ipString(remoteIP(conn)), err)
		return
	}
	var msg announceMessage
	if err := decodePeerPayload(raw, &msg); err != nil {
		return
	}
	if msg.Type != "announce" || msg.PublicKey != PublicKeyString(peerPub) {
		return
	}
	if !unixNowValid(msg.Timestamp) || msg.Nonce == "" {
		return
	}
	addr, err := m.announcedAddress(conn, msg)
	if err != nil {
		m.logger.Printf("peer announce address rejected: %v", err)
		return
	}
	if err := m.verifyAndStore(context.Background(), peerPub, addr, "announce"); err != nil {
		m.logger.Printf("peer announce %s (%s) failed verification: %v", msg.PublicKey, addr, err)
		m.registry.MarkPeerFailure(msg.PublicKey)
		return
	}
	m.writePeersResponse(conn, 64)
}

func (m *PeerManager) handleChallenge(conn net.Conn, env peerEnvelope, peerPub ed25519.PublicKey) {
	raw, err := verifyPeerEnvelope("challenge", env, peerPub)
	if err != nil {
		return
	}
	var msg challengeMessage
	if err := decodePeerPayload(raw, &msg); err != nil {
		return
	}
	if msg.Type != "challenge" || msg.Nonce == "" || !unixNowValid(msg.Timestamp) {
		return
	}
	response := challengeResponseMessage{
		Type:      "challenge_response",
		PublicKey: m.publicKey,
		Address:   m.settings.AdvertiseAddr,
		Nonce:     msg.Nonce,
		Timestamp: time.Now().Unix(),
	}
	_ = writePeerEnvelope(conn, m.identity, "challenge_response", response)
}

func (m *PeerManager) announcedAddress(conn net.Conn, msg announceMessage) (string, error) {
	if len(msg.Addresses) > 0 {
		return normalizePeerAddr(msg.Addresses[0], m.settings.PeerAllowPrivate)
	}
	if msg.Port > 0 {
		addr, err := peerAddressFromConn(conn, msg.Port)
		if err != nil {
			return "", err
		}
		return normalizePeerAddr(addr, m.settings.PeerAllowPrivate)
	}
	return "", errPeerAddress
}

func (m *PeerManager) writePeersResponse(conn net.Conn, limit int) {
	peers, err := m.registry.ListPeers(limit, true)
	if err != nil {
		return
	}
	out := make([]PeerInfo, 0, len(peers))
	for _, peer := range peers {
		if peer.PublicKey == m.publicKey {
			continue
		}
		out = append(out, PeerInfo{
			PublicKey: peer.PublicKey,
			Address:   peer.Address,
			LastSeen:  peer.LastSeen,
			Source:    peer.Source,
		})
	}
	_ = writePeerEnvelope(conn, m.identity, "peers", peersResponseMessage{
		Type:          "peers",
		NodePublicKey: m.publicKey,
		Timestamp:     time.Now().Unix(),
		Peers:         out,
	})
}

func (m *PeerManager) HandlePeersConn(conn net.Conn, peerPub ed25519.PublicKey) {
	if !m.peersLimiter.Allow(ipString(remoteIP(conn)) + "|" + publicKeyOrEmpty(peerPub)) {
		return
	}
	conn.SetDeadline(time.Now().Add(peerIOTimeout))
	defer conn.SetDeadline(time.Time{})

	env, err := readPeerFrame(conn)
	if err != nil {
		return
	}
	raw, err := verifyPeerEnvelope("peers_request", env, peerPub)
	if err != nil {
		return
	}
	var request peersRequestMessage
	if err := decodePeerPayload(raw, &request); err != nil {
		return
	}
	if request.Type != "peers_request" || !unixNowValid(request.Timestamp) {
		return
	}
	limit := request.Limit
	if limit <= 0 || limit > peerListMax {
		limit = 64
	}
	m.writePeersResponse(conn, limit)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// PeerDiscovery runs on clients and agents: it pulls signed peer lists,
// merges them, persists a cache and notifies subscribers.
type PeerDiscovery struct {
	settings *Settings
	logger   *log.Logger
	key      ed25519.PrivateKey

	mu          sync.RWMutex
	peers       map[string]PeerInfo
	subs        []func(PeerInfo)
	lastRequest map[string]time.Time
	knownKeys   map[string]string
}

func NewPeerDiscovery(s *Settings, logger *log.Logger) (*PeerDiscovery, error) {
	if s == nil || !s.PeerDiscovery {
		return nil, nil
	}
	keyFile := s.PeerKeyFile
	if keyFile == "" {
		keyFile = s.ClientKeyFile
	}
	if keyFile == "" {
		keyFile = "keys/peer.key"
	}
	key, err := LoadOrCreateKey(keyFile)
	if err != nil {
		return nil, err
	}
	d := &PeerDiscovery{
		settings:    s,
		logger:      logger,
		key:         key,
		peers:       map[string]PeerInfo{},
		lastRequest: map[string]time.Time{},
		knownKeys:   map[string]string{},
	}
	for _, addr := range s.effectiveNodeAddrs() {
		d.addPeer(PeerInfo{Address: addr, Source: "bootstrap"}, false)
	}
	for _, peer := range loadPeerCache(s.PeerCacheFile, s.PeerMax, s.PeerAllowPrivate) {
		d.addPeer(peer, false)
	}
	return d, nil
}

func (d *PeerDiscovery) Run(ctx context.Context) {
	if d == nil {
		return
	}
	d.refresh(ctx)
	interval := time.Duration(d.settings.PeerRefreshSeconds) * time.Second
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refresh(ctx)
		}
	}
}

func (d *PeerDiscovery) refresh(ctx context.Context) {
	d.mu.RLock()
	addrs := make([]string, 0, len(d.peers))
	for _, peer := range d.peers {
		addrs = append(addrs, peer.Address)
	}
	for _, addr := range d.settings.effectiveNodeAddrs() {
		addrs = append(addrs, addr)
	}
	d.mu.RUnlock()

	seen := map[string]bool{}
	sem := make(chan struct{}, 4)
	for _, addr := range addrs {
		addr = normalizePeerAddrLoose(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		d.mu.Lock()
		if ts, ok := d.lastRequest[addr]; ok && time.Since(ts) < time.Duration(d.settings.PeerRefreshSeconds)*time.Second/2 {
			d.mu.Unlock()
			continue
		}
		d.lastRequest[addr] = time.Now()
		d.mu.Unlock()

		sem <- struct{}{}
		go func(addr string) {
			defer func() { <-sem }()
			d.fetch(ctx, addr)
		}(addr)
	}
}

func (d *PeerDiscovery) fetch(ctx context.Context, addr string) {
	conn, err := dialTLSAddr(d.settings, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(peerConnectTimeout + peerIOTimeout))
	if err := peerHandshake(conn, d.key, connPeers, handshakeTimeout); err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(peerIOTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := writePeerEnvelope(conn, d.key, "peers_request", peersRequestMessage{
		Type:      "peers_request",
		Limit:     d.settings.PeerMax,
		Timestamp: time.Now().Unix(),
	}); err != nil {
		return
	}
	env, err := readPeerFrame(conn)
	if err != nil {
		return
	}
	var response peersResponseMessage
	if err := json.Unmarshal(env.Payload, &response); err != nil {
		return
	}
	if response.Type != "peers" {
		return
	}
	nodePub, err := ParsePublicKey(response.NodePublicKey)
	if err != nil {
		return
	}
	if _, err := verifyPeerEnvelope("peers", env, nodePub); err != nil {
		return
	}
	if !unixNowValid(response.Timestamp) {
		return
	}
	if !d.rememberNodeKey(addr, response.NodePublicKey) {
		return
	}
	for _, peer := range response.Peers {
		if peer.Source == "" {
			peer.Source = "gossip"
		}
		d.addPeer(peer, true)
	}
}

func (d *PeerDiscovery) rememberNodeKey(addr, key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.knownKeys[addr]; ok && existing != key {
		d.logger.Printf("peer %s changed node key; ignoring its peer list", addr)
		return false
	}
	d.knownKeys[addr] = key
	return true
}

func (d *PeerDiscovery) addPeer(peer PeerInfo, persist bool) {
	addr, err := normalizePeerAddr(peer.Address, d.settings.PeerAllowPrivate)
	if err != nil {
		// Bootstrap entries may be hostnames; keep them for dialing.
		if peer.Source == "bootstrap" {
			addr = normalizePeerAddrLoose(peer.Address)
		}
	}
	if addr == "" {
		return
	}
	if peer.PublicKey == "" && peer.Source != "bootstrap" {
		return
	}
	if peer.PublicKey != "" {
		if _, err := ParsePublicKey(peer.PublicKey); err != nil {
			return
		}
	}

	maxPeers := d.settings.PeerMax
	if maxPeers <= 0 {
		maxPeers = 64
	}
	d.mu.Lock()
	key := peer.PublicKey
	if key == "" {
		key = "addr:" + addr
	}
	if existing, ok := d.peers[key]; ok {
		existing.Address = addr
		existing.LastSeen = time.Now()
		if peer.Source != "" {
			existing.Source = peer.Source
		}
		d.peers[key] = existing
		d.mu.Unlock()
		if persist {
			d.save()
		}
		d.notify(existing)
		return
	}
	// Drop a bootstrap entry or a different key advertising the same address.
	// A keyed peer is never displaced by another key or an unkeyed entry.
	for oldKey, existing := range d.peers {
		if existing.Address != addr || oldKey == key {
			continue
		}
		if existing.PublicKey != "" && existing.PublicKey != peer.PublicKey {
			d.mu.Unlock()
			return
		}
		delete(d.peers, oldKey)
	}
	if len(d.peers) >= maxPeers {
		d.mu.Unlock()
		return
	}
	peer.Address = addr
	peer.LastSeen = time.Now()
	if peer.Source == "" {
		peer.Source = "gossip"
	}
	d.peers[key] = peer
	d.mu.Unlock()

	if persist {
		d.save()
	}
	d.notify(peer)
}

func (d *PeerDiscovery) save() {
	peers := d.Snapshot()
	if err := savePeerCache(d.settings.PeerCacheFile, peers); err != nil {
		d.logger.Printf("peer cache save failed: %v", err)
	}
}

func (d *PeerDiscovery) Snapshot() []PeerInfo {
	d.mu.RLock()
	out := make([]PeerInfo, 0, len(d.peers))
	for _, peer := range d.peers {
		out = append(out, peer)
	}
	d.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	maxPeers := d.settings.PeerMax
	if maxPeers <= 0 {
		maxPeers = 64
	}
	if len(out) > maxPeers {
		out = out[:maxPeers]
	}
	return out
}

func (d *PeerDiscovery) Subscribe(fn func(PeerInfo)) {
	if d == nil || fn == nil {
		return
	}
	d.mu.Lock()
	d.subs = append(d.subs, fn)
	existing := make([]PeerInfo, 0, len(d.peers))
	for _, peer := range d.peers {
		existing = append(existing, peer)
	}
	d.mu.Unlock()
	for _, peer := range existing {
		go fn(peer)
	}
}

func (d *PeerDiscovery) notify(peer PeerInfo) {
	d.mu.RLock()
	subs := append([]func(PeerInfo){}, d.subs...)
	d.mu.RUnlock()
	for _, fn := range subs {
		go fn(peer)
	}
}

func normalizePeerAddrLoose(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}

var (
	errUnexpectedPeerMessage = &peerError{"unexpected peer message"}
	errPeerKeyMismatch       = &peerError{"peer key mismatch"}
	errPeerChallengeMismatch = &peerError{"peer challenge mismatch"}
	errPeerTimestamp         = &peerError{"peer timestamp out of range"}
	errPeerAddress           = &peerError{"peer address missing"}
	errPeerStoreFull         = &peerError{"peer store is full"}
)

type peerError struct{ msg string }

func (e *peerError) Error() string { return e.msg }
