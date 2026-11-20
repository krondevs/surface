package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerEnvelopeRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := announceMessage{
		Type:      "announce",
		PublicKey: PublicKeyString(pub),
		Port:      9253,
		Timestamp: time.Now().Unix(),
		Nonce:     "abc123",
	}
	var buf bytes.Buffer
	if err := writePeerEnvelope(&buf, priv, "announce", msg); err != nil {
		t.Fatal(err)
	}
	env, err := readPeerFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := verifyPeerEnvelope("announce", env, pub)
	if err != nil {
		t.Fatal(err)
	}
	var got announceMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != msg.PublicKey || got.Nonce != msg.Nonce || got.Port != msg.Port {
		t.Fatalf("unexpected message: %+v", got)
	}

	tampered := env
	tampered.Payload = append([]byte(nil), env.Payload...)
	tampered.Payload[0] ^= 0xff
	if _, err := verifyPeerEnvelope("announce", tampered, pub); err == nil {
		t.Fatal("tampered payload should not verify")
	}
	if _, err := verifyPeerEnvelope("challenge", env, pub); err == nil {
		t.Fatal("wrong domain should not verify")
	}
}

func TestNormalizePeerAddr(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:9253", "[2001:4860:4860::8888]:9253"} {
		if _, err := normalizePeerAddr(addr, false); err != nil {
			t.Fatalf("public address %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{
		"127.0.0.1:9253",
		"10.1.2.3:9253",
		"192.168.1.1:9253",
		"100.64.0.1:9253",
		"169.254.1.1:9253",
		"example.com:9253",
		"[::1]:9253",
	} {
		if _, err := normalizePeerAddr(addr, false); err == nil {
			t.Fatalf("address %q should be rejected", addr)
		}
	}
	if _, err := normalizePeerAddr("127.0.0.1:9253", true); err != nil {
		t.Fatalf("loopback should be accepted when allowPrivate is set: %v", err)
	}
	if _, err := normalizeSeedAddr("seed.example.com:9253"); err != nil {
		t.Fatalf("seed hostname rejected: %v", err)
	}
}

func TestPeerCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	now := time.Now()
	peers := []PeerInfo{
		{PublicKey: "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Address: "8.8.8.8:9253", LastSeen: now, Source: "gossip"},
		{PublicKey: "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Address: "1.1.1.1:9253", LastSeen: now.Add(-time.Minute), Source: "seed"},
	}
	if err := savePeerCache(path, peers); err != nil {
		t.Fatal(err)
	}
	loaded := loadPeerCache(path, 64, false)
	if len(loaded) != 2 {
		t.Fatalf("loaded %d peers, want 2", len(loaded))
	}
	if loaded[0].Address != "8.8.8.8:9253" {
		t.Fatalf("unexpected first peer: %+v", loaded[0])
	}

	peers[0].LastSeen = now.Add(-peerTTL - time.Hour)
	if err := savePeerCache(path, peers); err != nil {
		t.Fatal(err)
	}
	loaded = loadPeerCache(path, 64, false)
	if len(loaded) != 1 || loaded[0].Address != "1.1.1.1:9253" {
		t.Fatalf("expired peer not removed: %+v", loaded)
	}

	peers = []PeerInfo{
		{Address: "127.0.0.1:9253", LastSeen: now},
		{Address: "8.8.4.4:9253", LastSeen: now},
	}
	if err := savePeerCache(path, peers); err != nil {
		t.Fatal(err)
	}
	loaded = loadPeerCache(path, 64, false)
	if len(loaded) != 1 || loaded[0].Address != "8.8.4.4:9253" {
		t.Fatalf("private peer should be dropped: %+v", loaded)
	}
}

func TestPeerStoreLifecycle(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(db)
	now := time.Now()
	peer := NodePeer{
		PublicKey:  "ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Address:    "8.8.8.8:9253",
		Status:     peerStatusVerified,
		Source:     "announce",
		FirstSeen:  now,
		LastSeen:   now,
		LastVerify: now,
		ExpiresAt:  now.Add(peerTTL),
	}
	if err := registry.UpsertPeer(peer); err != nil {
		t.Fatal(err)
	}
	got, err := registry.FindPeer(peer.PublicKey)
	if err != nil || got.Address != peer.Address {
		t.Fatalf("find peer: %+v, %v", got, err)
	}
	if count, err := registry.CountPeers(true); err != nil || count != 1 {
		t.Fatalf("count verified = %d, %v", count, err)
	}
	if err := registry.MarkPeerFailure(peer.PublicKey); err != nil {
		t.Fatal(err)
	}
	if peers, err := registry.ListPeers(10, true); err != nil || len(peers) != 0 {
		t.Fatalf("failed peer still listed as verified: %+v, %v", peers, err)
	}
	if err := registry.UpsertPeer(peer); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ExpirePeers(now.Add(peerTTL + time.Hour)); err != nil {
		t.Fatal(err)
	}
	if count, err := registry.CountPeers(false); err != nil || count != 0 {
		t.Fatalf("expired peer count = %d, %v", count, err)
	}
}

func TestPeerDiscoveryConflictKeepsExistingKey(t *testing.T) {
	dir := t.TempDir()
	s := defaultSettings()
	s.PeerAllowPrivate = true
	s.PeerMax = 10
	s.PeerKeyFile = filepath.Join(dir, "peer.key")
	s.PeerCacheFile = filepath.Join(dir, "peers.json")
	s.SeedNodes = []string{}
	s.NodeAddr = ""
	s.NodeAddrs = nil
	d, err := NewPeerDiscovery(s, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	first := PeerInfo{PublicKey: publicKeyForTest(), Address: "127.0.0.1:9253", Source: "gossip"}
	d.addPeer(first, false)
	second := PeerInfo{PublicKey: publicKeyForTest(), Address: "127.0.0.1:9253", Source: "gossip"}
	d.addPeer(second, false)
	unkeyed := PeerInfo{Address: "127.0.0.1:9253", Source: "gossip"}
	d.addPeer(unkeyed, false)
	snapshot := d.Snapshot()
	if len(snapshot) != 1 || snapshot[0].PublicKey != first.PublicKey {
		t.Fatalf("address conflict replaced the existing key: %+v", snapshot)
	}
}

func publicKeyForTest() string {
	pub, _, _ := ed25519.GenerateKey(nil)
	return PublicKeyString(pub)
}
