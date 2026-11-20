package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/yamux"
	"gorm.io/gorm"
)

type Node struct {
	settings  *Settings
	db        *gorm.DB
	registry  *Registry
	sessions  *SessionManager
	internet  *InternetDialer
	peers     *PeerManager
	identity  ed25519.PrivateKey
	publicKey string
	logger    *log.Logger
}

func runNode(ctx context.Context, s *Settings, logger *log.Logger) error {
	db, err := OpenDB(s.DBName)
	if err != nil {
		return err
	}
	internet, err := NewInternetDialer(s.DNServers, s.ExitProxy, s.OnionProxy, s.ExitProxyFallbackDirect, logger)
	if err != nil {
		return err
	}
	nodeKeyFile := s.NodeKeyFile
	if nodeKeyFile == "" {
		nodeKeyFile = "keys/node.key"
	}
	nodeKey, err := LoadOrCreateKey(nodeKeyFile)
	if err != nil {
		return err
	}
	publicKey := PublicKeyString(nodeKey.Public().(ed25519.PublicKey))
	node := &Node{
		settings:  s,
		db:        db,
		registry:  NewRegistry(db),
		sessions:  NewSessionManager(),
		internet:  internet,
		identity:  nodeKey,
		publicKey: publicKey,
		logger:    logger,
	}
	node.peers = NewPeerManager(s, node.registry, nodeKey, logger)
	logger.Printf("node public key: %s", publicKey)
	go node.peers.Run(ctx)
	clearnetExit := internet.ExitDescription()
	onionExit := internet.OnionDescription()
	logger.Printf("internet exit: %s; onion exit: %s", clearnetExit, onionExit)
	if onionExit == "disabled" {
		logger.Printf("onion destinations disabled: set onion_proxy to a Tor SOCKS5 (e.g. socks5://127.0.0.1:9050)")
	} else if clearnetExit != "direct" && clearnetExit == onionExit {
		logger.Printf("warning: exit_proxy and onion_proxy are the same; clearnet traffic also uses Tor")
	}
	if err := ensureTLSCert(s.TLSCertFile, s.TLSKeyFile); err != nil {
		return err
	}
	if err := node.startTunnelListener(ctx); err != nil {
		return err
	}
	go node.runSweeper(ctx)

	if s.ProxyListen != "" && s.ProxyListen != "off" {
		proxy := NewProxyServer(s.ProxyListen, node, logger)
		go func() {
			if err := proxy.Start(ctx); err != nil {
				logger.Printf("proxy stopped: %v", err)
			}
		}()
	}
	if s.HealthListen != "" {
		go startHealthServer(s.HealthListen, node, logger)
	}

	<-ctx.Done()
	node.sessions.CloseAll()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}
	logger.Printf("node shutdown complete")
	return nil
}

func (n *Node) startTunnelListener(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(n.settings.TLSCertFile, n.settings.TLSKeyFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	listener, err := tls.Listen("tcp", n.settings.TunnelListen, cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	n.logger.Printf("tunnel listener on %s", n.settings.TunnelListen)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go n.handleTunnelConn(conn)
		}
	}()
	return nil
}

func (n *Node) handleTunnelConn(conn net.Conn) {
	defer conn.Close()
	ctype, pub, err := readPeerHandshake(conn, handshakeTimeout)
	if err != nil {
		return
	}
	publicKey := PublicKeyString(pub)

	switch ctype {
	case connRegister:
		if !n.agentAllowed(publicKey) {
			writeStatus(conn, 2)
			return
		}
		if err := writeStatus(conn, 0); err != nil {
			return
		}
		reg, err := readRegistration(conn, handshakeTimeout)
		if err != nil {
			return
		}
		name := NormalizeHost(reg.Name)
		if name != DeriveName(pub) || len(reg.Services) == 0 {
			return
		}
		mux, err := yamux.Client(conn, yamuxConfig())
		if err != nil {
			return
		}
		sessionID := randomID()
		n.sessions.Add(&Session{
			ID:        sessionID,
			PublicKey: publicKey,
			Name:      name,
			Role:      "agent",
			E2E:       reg.E2E,
			Conn:      conn,
			Mux:       mux,
			CreatedAt: time.Now(),
		})
		for _, svc := range reg.Services {
			n.registry.UpsertService(name, publicKey, svc.VirtualPort, sessionID)
		}
		n.logger.Printf("agent registered name=%s services=%d", name, len(reg.Services))
		<-mux.CloseChan()
		n.registry.MarkSessionOffline(sessionID)
		n.sessions.Remove(sessionID)
		n.logger.Printf("agent disconnected name=%s", name)

	case connRequest:
		if !n.clientAllowed(publicKey) {
			writeStatus(conn, 2)
			return
		}
		if err := writeStatus(conn, 0); err != nil {
			return
		}
		mux, err := yamux.Server(conn, yamuxConfig())
		if err != nil {
			return
		}
		sessionID := randomID()
		n.sessions.Add(&Session{
			ID:        sessionID,
			PublicKey: publicKey,
			Role:      "client",
			Conn:      conn,
			Mux:       mux,
			CreatedAt: time.Now(),
		})
		n.logger.Printf("client connected key=%s", publicKey)
		for {
			stream, err := mux.Accept()
			if err != nil {
				break
			}
			go n.handleRequestStream(stream)
		}
		n.sessions.Remove(sessionID)

	case connNode:
		if !n.nodeAllowed(publicKey) {
			writeStatus(conn, 2)
			return
		}
		if err := writeStatus(conn, 0); err != nil {
			return
		}
		n.peers.HandleNodeConn(conn, pub)

	case connPeers:
		if err := writeStatus(conn, 0); err != nil {
			return
		}
		n.peers.HandlePeersConn(conn, pub)

	default:
		writeStatus(conn, 5)
	}
}

func (n *Node) handleRequestStream(stream net.Conn) {
	defer stream.Close()
	host, port, v2, err := readRequest(stream)
	if err != nil {
		return
	}
	host = NormalizeHost(host)

	if !v2 {
		// Legacy v1 client: no metadata, no E2E. Clearnet keeps working; an
		// old client talking to a new agent will fail the E2E handshake, so
		// plaintext .surface traffic never reaches a service.
		upstream, err := n.DialTarget(host, port)
		if err != nil {
			return
		}
		pipe(stream, upstream)
		return
	}

	if IsSurfaceName(host) {
		service, err := n.registry.Lookup(host, port)
		if err != nil {
			writeResponseHeader(stream, respNotFound, false, nil, 0)
			return
		}
		session, ok := n.sessions.Get(service.SessionID)
		if !ok {
			writeResponseHeader(stream, respNotFound, false, nil, 0)
			return
		}
		if !session.E2E {
			writeResponseHeader(stream, respE2EUnavailable, false, nil, 0)
			return
		}
		pub, err := ParsePublicKey(service.PublicKey)
		if err != nil {
			writeResponseHeader(stream, respBadRequest, false, nil, 0)
			return
		}
		upstream, err := session.Mux.Open()
		if err != nil {
			writeResponseHeader(stream, respNotFound, false, nil, 0)
			return
		}
		if err := writeVirtualPort(upstream, port); err != nil {
			upstream.Close()
			writeResponseHeader(stream, respBadRequest, false, nil, 0)
			return
		}
		if err := writeResponseHeader(stream, respOK, true, pub, e2eVersion1); err != nil {
			upstream.Close()
			return
		}
		pipe(stream, upstream)
		return
	}

	upstream, err := n.internet.DialTarget(host, port)
	if err != nil {
		if IsOnionName(host) {
			writeResponseHeader(stream, respExitUnavailable, false, nil, 0)
		} else {
			writeResponseHeader(stream, respNotFound, false, nil, 0)
		}
		return
	}
	if err := writeResponseHeader(stream, respOK, false, nil, 0); err != nil {
		upstream.Close()
		return
	}
	pipe(stream, upstream)
}

func (n *Node) DialTarget(host string, port int) (net.Conn, error) {
	host = NormalizeHost(host)
	if IsSurfaceName(host) {
		service, err := n.registry.Lookup(host, port)
		if err != nil {
			return nil, err
		}
		session, ok := n.sessions.Get(service.SessionID)
		if !ok {
			return nil, errServiceNotFound
		}
		stream, err := session.Mux.Open()
		if err != nil {
			return nil, err
		}
		if err := writeVirtualPort(stream, port); err != nil {
			stream.Close()
			return nil, err
		}
		return stream, nil
	}
	return n.internet.DialTarget(host, port)
}

func (n *Node) runSweeper(ctx context.Context) {
	interval := time.Duration(n.settings.HeartbeatSecond) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, session := range n.sessions.Snapshot() {
				if session.Role == "agent" {
					n.registry.Heartbeat(session.ID)
				}
			}
		}
	}
}

func (n *Node) agentAllowed(publicKey string) bool {
	if key, err := n.registry.FindNodeKey(publicKey); err == nil {
		return key.Enabled && key.Role == "agent"
	}
	if len(n.settings.AllowedAgents) == 0 {
		return true
	}
	for _, allowed := range n.settings.AllowedAgents {
		if allowed == publicKey {
			return true
		}
	}
	return false
}

func (n *Node) nodeAllowed(publicKey string) bool {
	if key, err := n.registry.FindNodeKey(publicKey); err == nil {
		return key.Enabled && key.Role == "node"
	}
	if len(n.settings.AllowedNodes) == 0 {
		return true
	}
	for _, allowed := range n.settings.AllowedNodes {
		pub, err := ParsePublicKey(allowed)
		if err == nil && PublicKeyString(pub) == publicKey {
			return true
		}
	}
	return false
}

func (n *Node) clientAllowed(publicKey string) bool {
	keys, err := n.registry.ListNodeKeys()
	if err != nil {
		return true
	}
	hasClients := false
	for _, key := range keys {
		if key.Role != "client" {
			continue
		}
		hasClients = true
		if key.PublicKey == publicKey && key.Enabled {
			return true
		}
	}
	return !hasClients
}

func ensureTLSCert(certFile, keyFile string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "surface-node"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(certFile); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0o600)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func errNoServices() error {
	return errors.New("no services configured")
}
