package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPeerDiscoveryBetweenNodes(t *testing.T) {
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)

	hidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DISCOVERED_SERVICE")
	}))
	defer hidden.Close()
	hiddenAddr := strings.TrimPrefix(hidden.URL, "http://")

	seedTunnel := freeAddr(t)
	nodeTunnel := freeAddr(t)

	seedKeyPath := filepath.Join(dir, "seed", "node.key")
	seedKey, err := LoadOrCreateKey(seedKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeKeyPath := filepath.Join(dir, "node", "node.key")
	nodeKey, err := LoadOrCreateKey(nodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	nodePub := PublicKeyString(nodeKey.Public().(ed25519.PublicKey))
	_ = seedKey

	seedSettings := &Settings{
		Role:                    "node",
		DBName:                  filepath.Join(dir, "seed.db"),
		TunnelListen:            seedTunnel,
		ProxyListen:             "off",
		TLSCertFile:             filepath.Join(dir, "seed.crt"),
		TLSKeyFile:              filepath.Join(dir, "seed.key"),
		NodeKeyFile:             seedKeyPath,
		NodeAuth:                "none",
		TLSSkipVerify:           true,
		PeerDiscovery:           true,
		PeerAllowPrivate:        true,
		SeedNodes:               []string{},
		PeerRefreshSeconds:      30,
		PeerMax:                 64,
		DNServers:               []string{"1.1.1.1:53"},
		HeartbeatSecond:         5,
		HeartbeatTimeoutSeconds: 15,
	}
	seedSettings.applyDefaults()

	nodeSettings := &Settings{
		Role:                    "node",
		DBName:                  filepath.Join(dir, "node.db"),
		TunnelListen:            nodeTunnel,
		ProxyListen:             "off",
		TLSCertFile:             filepath.Join(dir, "node.crt"),
		TLSKeyFile:              filepath.Join(dir, "node-tls.key"),
		NodeKeyFile:             nodeKeyPath,
		NodeAuth:                "none",
		TLSSkipVerify:           true,
		PeerDiscovery:           true,
		PeerAllowPrivate:        true,
		SeedNodes:               []string{seedTunnel},
		AdvertiseAddr:           nodeTunnel,
		PeerRefreshSeconds:      30,
		PeerMax:                 64,
		DNServers:               []string{"1.1.1.1:53"},
		HeartbeatSecond:         5,
		HeartbeatTimeoutSeconds: 15,
	}
	nodeSettings.applyDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := runNode(ctx, seedSettings, logger); err != nil {
			logger.Printf("seed node stopped: %v", err)
		}
	}()
	go func() {
		if err := runNode(ctx, nodeSettings, logger); err != nil {
			logger.Printf("peer node stopped: %v", err)
		}
	}()

	waitForPeer(t, seedSettings.DBName, nodePub, 20*time.Second)

	clientAddr := freeAddr(t)
	clientSettings := &Settings{
		Role:               "client",
		NodeAddr:           seedTunnel,
		NodeAuth:           "none",
		TLSSkipVerify:      true,
		ProxyListen:        clientAddr,
		ClientKeyFile:      filepath.Join(dir, "client.key"),
		PeerKeyFile:        filepath.Join(dir, "client-peer.key"),
		PeerCacheFile:      filepath.Join(dir, "client-peers.json"),
		PeerDiscovery:      true,
		PeerAllowPrivate:   true,
		PeerRefreshSeconds: 30,
		PeerMax:            64,
		HeartbeatSecond:    5,
	}
	clientSettings.applyDefaults()
	go func() { _ = runClient(ctx, clientSettings, logger) }()

	waitForCachePeer(t, clientSettings.PeerCacheFile, nodeTunnel, 20*time.Second)

	identityDir := filepath.Join(dir, "agent-identity")
	agentKey, err := LoadOrCreateKey(filepath.Join(identityDir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	agentName := DeriveName(agentKey.Public().(ed25519.PublicKey))
	agentSettings := &Settings{
		Role:               "agent",
		NodeAddr:           seedTunnel,
		NodeAuth:           "none",
		TLSSkipVerify:      true,
		IdentityDir:        identityDir,
		HiddenServices:     []HiddenService{{Alias: "discovered", IdentityDir: identityDir, VirtualPort: 80, Target: hiddenAddr}},
		ClientKeyFile:      filepath.Join(dir, "agent-client.key"),
		PeerKeyFile:        filepath.Join(dir, "agent-peer.key"),
		PeerCacheFile:      filepath.Join(dir, "agent-peers.json"),
		PeerDiscovery:      true,
		PeerAllowPrivate:   true,
		PeerRefreshSeconds: 30,
		PeerMax:            64,
		HeartbeatSecond:    5,
	}
	agentSettings.applyDefaults()
	go func() { _ = runAgent(ctx, agentSettings, logger) }()

	waitForService(t, nodeSettings.DBName, agentName, 25*time.Second)

	client2Addr := freeAddr(t)
	client2Settings := &Settings{
		Role:            "client",
		NodeAddr:        nodeTunnel,
		NodeAuth:        "none",
		TLSSkipVerify:   true,
		ProxyListen:     client2Addr,
		ClientKeyFile:   filepath.Join(dir, "client2.key"),
		PeerDiscovery:   false,
		HeartbeatSecond: 5,
	}
	client2Settings.applyDefaults()
	go func() { _ = runClient(ctx, client2Settings, logger) }()

	assertViaProxy(t, client2Addr, agentName, 80, "DISCOVERED_SERVICE")
}

func waitForPeer(t *testing.T, dbPath, publicKey string, timeout time.Duration) {
	t.Helper()
	time.Sleep(time.Second)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		db, err := OpenDB(dbPath)
		if err == nil {
			_, findErr := NewRegistry(db).FindPeer(publicKey)
			if sqlDB, dbErr := db.DB(); dbErr == nil {
				sqlDB.Close()
			}
			if findErr == nil {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("peer %s was not stored in %s", publicKey, dbPath)
}

func waitForService(t *testing.T, dbPath, name string, timeout time.Duration) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		db, err := OpenDB(dbPath)
		if err == nil {
			services, listErr := NewRegistry(db).ListServices()
			if sqlDB, dbErr := db.DB(); dbErr == nil {
				sqlDB.Close()
			}
			if listErr == nil {
				for _, service := range services {
					if service.Name == name {
						return
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("service %s was not registered in %s", name, dbPath)
}

func waitForCachePeer(t *testing.T, path, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, peer := range loadPeerCache(path, 64, true) {
			if peer.Address == address {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("peer %s was not cached in %s", address, path)
}
