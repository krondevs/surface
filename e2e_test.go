package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEd25519X25519Conversion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := ed25519PrivateToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	xPub, err := ed25519PublicToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := x25519Public(xPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, xPub) {
		t.Fatalf("x25519 public key mismatch: derived=%x converted=%x", derived, xPub)
	}
	if len(xPub) != 32 {
		t.Fatalf("unexpected x25519 key length: %d", len(xPub))
	}
}

// TestNoiseRelaySeesNoPlaintext runs a full client/agent E2E handshake through
// a relay that records every byte it forwards. The relay must only ever see
// ciphertext.
func TestNoiseRelaySeesNoPlaintext(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := DeriveName(pub)
	port := 80
	secret := "SURFACE_SUPER_SECRET_PAYLOAD"

	clientSide, relayClient := net.Pipe()
	relayAgent, agentSide := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{clientSide, relayClient, relayAgent, agentSide} {
		c.SetDeadline(deadline)
	}

	var mu sync.Mutex
	var seen []byte
	record := func(p []byte) {
		mu.Lock()
		seen = append(seen, p...)
		mu.Unlock()
	}

	// Relay both directions, recording the raw bytes.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := relayClient.Read(buf)
			if n > 0 {
				record(buf[:n])
				if _, werr := relayAgent.Write(buf[:n]); werr != nil {
					relayAgent.Close()
					return
				}
			}
			if err != nil {
				relayAgent.Close()
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := relayAgent.Read(buf)
			if n > 0 {
				record(buf[:n])
				if _, werr := relayClient.Write(buf[:n]); werr != nil {
					relayClient.Close()
					return
				}
			}
			if err != nil {
				relayClient.Close()
				return
			}
		}
	}()

	agentErr := make(chan error, 1)
	go func() {
		secure, err := acceptE2E(agentSide, priv, name, port)
		if err != nil {
			agentErr <- err
			return
		}
		got := make([]byte, len(secret))
		if _, err := io.ReadFull(secure, got); err != nil {
			agentErr <- err
			return
		}
		if string(got) != secret {
			agentErr <- fmt.Errorf("agent got %q, want %q", got, secret)
			return
		}
		agentErr <- nil
	}()

	clientConn, err := dialE2E(clientSide, pub, name, port)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := clientConn.Write([]byte(secret)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := <-agentErr; err != nil {
		t.Fatalf("agent: %v", err)
	}

	mu.Lock()
	observed := string(seen)
	mu.Unlock()
	if strings.Contains(observed, secret) {
		t.Fatal("the relay saw the plaintext payload")
	}
	if strings.Contains(observed, "surface-e2e-v1") {
		t.Fatal("the relay saw the prologue in plaintext")
	}
}

func TestNoiseHandshakeBidirectional(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := DeriveName(pub)
	clientSide, agentSide := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	clientSide.SetDeadline(deadline)
	agentSide.SetDeadline(deadline)

	type result struct {
		conn net.Conn
		err  error
	}
	agentCh := make(chan result, 1)
	go func() {
		conn, err := acceptE2E(agentSide, priv, name, 443)
		agentCh <- result{conn, err}
	}()
	clientConn, err := dialE2E(clientSide, pub, name, 443)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	agentRes := <-agentCh
	if agentRes.err != nil {
		t.Fatalf("agent handshake: %v", agentRes.err)
	}
	agentConn := agentRes.conn

	// Client -> agent
	go func() {
		clientConn.Write([]byte("ping-from-client"))
	}()
	buf := make([]byte, len("ping-from-client"))
	if _, err := io.ReadFull(agentConn, buf); err != nil {
		t.Fatalf("agent read: %v", err)
	}
	if string(buf) != "ping-from-client" {
		t.Fatalf("agent got %q", buf)
	}

	// Agent -> client
	go func() {
		agentConn.Write([]byte("pong-from-agent"))
	}()
	buf = make([]byte, len("pong-from-agent"))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong-from-agent" {
		t.Fatalf("client got %q", buf)
	}
}

func TestNoisePrologueMismatchFails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := DeriveName(pub)
	clientSide, agentSide := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	clientSide.SetDeadline(deadline)
	agentSide.SetDeadline(deadline)

	go func() {
		defer agentSide.Close()
		// Agent thinks the requested port is 81.
		acceptE2E(agentSide, priv, name, 81)
	}()
	// Client asks for port 80: prologue mismatch.
	if _, err := dialE2E(clientSide, pub, name, 80); err == nil {
		t.Fatal("expected the handshake to fail on prologue mismatch")
	}
}

func TestNoiseWrongAgentKeyFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	realPub := priv.Public().(ed25519.PublicKey)
	name := DeriveName(realPub)
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	clientSide, agentSide := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	clientSide.SetDeadline(deadline)
	agentSide.SetDeadline(deadline)

	go func() {
		defer agentSide.Close()
		acceptE2E(agentSide, priv, name, 80)
	}()
	if _, err := dialE2E(clientSide, wrongPub, name, 80); err == nil {
		t.Fatal("expected the handshake to fail with the wrong agent key")
	}
}

func TestProtocolV2RequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRequestHeaderV2(&buf, "ABC.Surface", 443); err != nil {
		t.Fatal(err)
	}
	host, port, v2, err := readRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !v2 || host != "abc.surface" || port != 443 {
		t.Fatalf("got host=%q port=%d v2=%t", host, port, v2)
	}
}

func TestProtocolV1RequestStillReadable(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRequestHeader(&buf, "example.com", 80); err != nil {
		t.Fatal(err)
	}
	host, port, v2, err := readRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if v2 || host != "example.com" || port != 80 {
		t.Fatalf("got host=%q port=%d v2=%t", host, port, v2)
	}
}

func TestProtocolResponseRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := writeResponseHeader(&buf, respOK, true, pub, e2eVersion1); err != nil {
		t.Fatal(err)
	}
	status, e2e, gotPub, version, err := readResponseHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if status != respOK || !e2e || version != e2eVersion1 || !bytes.Equal(gotPub, pub) {
		t.Fatalf("unexpected response: status=%d e2e=%t version=%d", status, e2e, version)
	}

	var clear bytes.Buffer
	if err := writeResponseHeader(&clear, respOK, false, nil, 0); err != nil {
		t.Fatal(err)
	}
	status, e2e, gotPub, version, err = readResponseHeader(&clear)
	if err != nil {
		t.Fatal(err)
	}
	if status != respOK || e2e || gotPub != nil || version != 0 {
		t.Fatalf("unexpected clearnet response: status=%d e2e=%t version=%d", status, e2e, version)
	}

	var fail bytes.Buffer
	if err := writeResponseHeader(&fail, respE2EUnavailable, false, nil, 0); err != nil {
		t.Fatal(err)
	}
	status, e2e, _, _, err = readResponseHeader(&fail)
	if err != nil {
		t.Fatal(err)
	}
	if status != respE2EUnavailable || e2e {
		t.Fatalf("unexpected error response: status=%d e2e=%t", status, e2e)
	}
}

func TestNodeAuth(t *testing.T) {
	s := &Settings{}
	s.applyDefaults()
	if s.effectiveNodeAuth() != "pinned" {
		t.Fatalf("default node auth = %q, want pinned", s.effectiveNodeAuth())
	}
	s = &Settings{NodeAuth: "NONE"}
	if s.effectiveNodeAuth() != "none" {
		t.Fatalf("node auth = %q, want none", s.effectiveNodeAuth())
	}
	if err := (&Settings{NodeAuth: "bogus"}).validate(); err == nil {
		t.Fatal("expected error for invalid node_auth")
	}
}

// TestNodeRejectsPlaintextSurface ensures a v2 client gets an explicit
// e2e-unavailable status when the agent did not advertise E2E.
func TestNodeRejectsPlaintextSurface(t *testing.T) {
	db, err := OpenDB(t.TempDir() + "/node.db")
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(db)
	sessions := NewSessionManager()
	node := &Node{registry: registry, sessions: sessions}

	sessions.Add(&Session{
		ID:        "legacy",
		PublicKey: "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
		Name:      "abc.surface",
		Role:      "agent",
		E2E:       false,
	})
	if err := registry.UpsertService("abc.surface", "ed25519:0000000000000000000000000000000000000000000000000000000000000000", 80, "legacy"); err != nil {
		t.Fatal(err)
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	deadline := time.Now().Add(3 * time.Second)
	clientSide.SetDeadline(deadline)
	serverSide.SetDeadline(deadline)

	go node.handleRequestStream(serverSide)

	if err := writeRequestHeaderV2(clientSide, "abc.surface", 80); err != nil {
		t.Fatal(err)
	}
	status, _, _, _, err := readResponseHeader(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if status != respE2EUnavailable {
		t.Fatalf("status = %d, want respE2EUnavailable", status)
	}
}

// TestNodeV1ClearnetCompatibility verifies that a legacy v1 client can still
// use clearnet through a v2 node.
func TestNodeV1ClearnetCompatibility(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "V1_CLEARNET")
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)

	dialer, err := NewInternetDialer(nil, "", "", false, logger)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{internet: dialer, logger: logger}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	deadline := time.Now().Add(5 * time.Second)
	clientSide.SetDeadline(deadline)
	serverSide.SetDeadline(deadline)
	go node.handleRequestStream(serverSide)

	if err := writeRequestHeader(clientSide, host, port); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(clientSide, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "V1_CLEARNET") {
		t.Fatalf("unexpected body %q", body)
	}
}
