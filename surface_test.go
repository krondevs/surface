package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDeriveName(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := DeriveName(priv.Public().(ed25519.PublicKey))
	if !strings.HasSuffix(name, ".surface") {
		t.Fatalf("name %q missing .surface suffix", name)
	}
	if len(name) != 16+len(".surface") {
		t.Fatalf("unexpected name length: %d (%q)", len(name), name)
	}
	_, priv2, _ := ed25519.GenerateKey(nil)
	if other := DeriveName(priv2.Public().(ed25519.PublicKey)); other == name {
		t.Fatal("distinct keys produced the same name")
	}
	if !IsSurfaceName(name) {
		t.Fatalf("%q should be a surface name", name)
	}
}

func TestRequestHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRequestHeader(&buf, "ABC.Surface", 443); err != nil {
		t.Fatal(err)
	}
	host, port, err := readRequestHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if host != "abc.surface" || port != 443 {
		t.Fatalf("got %q:%d", host, port)
	}
}

func TestRegistrationRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	reg := Registration{Name: "abc.surface", Services: []ServiceDeclaration{{VirtualPort: 80, Alias: "blog"}}}
	go func() {
		writeRegistration(client, reg)
	}()
	got, err := readRegistration(server, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != reg.Name || len(got.Services) != 1 || got.Services[0].VirtualPort != 80 {
		t.Fatalf("unexpected registration: %+v", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com:8080", "example.com", 8080},
		{"example.com", "example.com", 80},
		{"1.2.3.4:443", "1.2.3.4", 443},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in, 80)
		if host != c.host || port != c.port {
			t.Fatalf("splitHostPort(%q) = %q,%d want %q,%d", c.in, host, port, c.host, c.port)
		}
	}
}

func TestRegistryLifecycle(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(db)

	if err := registry.UpsertService("abc.surface", "ed25519:aa", 80, "sess1"); err != nil {
		t.Fatal(err)
	}
	service, err := registry.Lookup("abc.surface", 80)
	if err != nil {
		t.Fatal(err)
	}
	if service.SessionID != "sess1" || service.Status != statusOnline {
		t.Fatalf("unexpected service: %+v", service)
	}
	if err := registry.MarkSessionOffline("sess1"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Lookup("abc.surface", 80); err != errServiceNotFound {
		t.Fatalf("expected not found after offline, got %v", err)
	}

	if err := registry.UpsertNodeKey("agent1", "ed25519:bb", "agent", true); err != nil {
		t.Fatal(err)
	}
	key, err := registry.FindNodeKey("ed25519:bb")
	if err != nil {
		t.Fatal(err)
	}
	if !key.Enabled || key.Role != "agent" {
		t.Fatalf("unexpected key: %+v", key)
	}
	if err := registry.SetNodeKeyEnabled("ed25519:bb", false); err != nil {
		t.Fatal(err)
	}
	key, _ = registry.FindNodeKey("ed25519:bb")
	if key.Enabled {
		t.Fatal("key should be disabled")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)

	hidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_HIDDEN")
	}))
	defer hidden.Close()
	internet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_INTERNET")
	}))
	defer internet.Close()

	hiddenAddr := strings.TrimPrefix(hidden.URL, "http://")
	internetAddr := strings.TrimPrefix(internet.URL, "http://")
	_, hiddenPortStr, _ := net.SplitHostPort(hiddenAddr)
	hiddenPort, _ := strconv.Atoi(hiddenPortStr)
	internetHost, internetPortStr, _ := net.SplitHostPort(internetAddr)
	internetPort, _ := strconv.Atoi(internetPortStr)

	nodeTunnel := freeAddr(t)
	nodeSettings := &Settings{
		Role:                    "node",
		DBName:                  filepath.Join(dir, "node.db"),
		TunnelListen:            nodeTunnel,
		ProxyListen:             "off",
		TLSCertFile:             filepath.Join(dir, "node.crt"),
		TLSKeyFile:              filepath.Join(dir, "node.key"),
		DNServers:               []string{"1.1.1.1:53"},
		HeartbeatSecond:         5,
		HeartbeatTimeoutSeconds: 15,
	}
	nodeSettings.applyDefaults()

	agentDir := filepath.Join(dir, "agent")
	agentPriv, err := LoadOrCreateKey(filepath.Join(agentDir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	agentName := DeriveName(agentPriv.Public().(ed25519.PublicKey))
	agentSettings := &Settings{
		Role:            "agent",
		NodeAddr:        nodeTunnel,
		TLSSkipVerify:   true,
		IdentityDir:     agentDir,
		HeartbeatSecond: 5,
		HiddenServices:  []HiddenService{{Alias: "hidden", VirtualPort: hiddenPort, Target: hiddenAddr}},
	}

	clientAddr := freeAddr(t)
	clientSettings := &Settings{
		Role:            "client",
		NodeAddr:        nodeTunnel,
		TLSSkipVerify:   true,
		ProxyListen:     clientAddr,
		ClientKeyFile:   filepath.Join(dir, "client.key"),
		HeartbeatSecond: 5,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runNode(ctx, nodeSettings, logger) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = runAgent(ctx, agentSettings, logger) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = runClient(ctx, clientSettings, logger) }()

	assertViaProxy(t, clientAddr, agentName, hiddenPort, "SURFACE_HIDDEN")
	assertViaProxy(t, clientAddr, internetHost, internetPort, "SURFACE_INTERNET")
}

func assertViaProxy(t *testing.T, proxyAddr, host string, port int, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		body, err := socks5Get(proxyAddr, host, port)
		if err == nil && strings.Contains(body, want) {
			return
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("proxy request for %s:%d failed: %v", host, port, lastErr)
}

func socks5Get(proxyAddr, host string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	negotiation := make([]byte, 2)
	if _, err := io.ReadFull(conn, negotiation); err != nil {
		return "", err
	}

	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	request = append(request, portBuf[:]...)
	if _, err := conn.Write(request); err != nil {
		return "", err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", err
	}
	if reply[1] != 0x00 {
		return "", fmt.Errorf("socks5 connect failed with code %d", reply[1])
	}

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func TestPinnedCertificateVerification(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.crt")
	if err := ensureTLSCert(certFile, filepath.Join(dir, "node.key")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseCertificatePEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	verify := verifyPinnedCertificate(pinnedKeyFingerprint(cert))
	if err := verify([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("expected pinned certificate to verify, got %v", err)
	}

	otherDir := t.TempDir()
	otherFile := filepath.Join(otherDir, "node.crt")
	if err := ensureTLSCert(otherFile, filepath.Join(otherDir, "node.key")); err != nil {
		t.Fatal(err)
	}
	otherRaw, err := os.ReadFile(otherFile)
	if err != nil {
		t.Fatal(err)
	}
	other, err := parseCertificatePEM(otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify([][]byte{other.Raw}, nil); err == nil {
		t.Fatal("expected a different certificate to fail pin verification")
	}
}

func TestClientAuthorization(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(db)
	node := &Node{registry: registry}

	if !node.clientAllowed("ed25519:aa") {
		t.Fatal("expected open registration when no client keys exist")
	}
	if err := registry.UpsertNodeKey("", "ed25519:aa", "client", true); err != nil {
		t.Fatal(err)
	}
	if !node.clientAllowed("ed25519:aa") {
		t.Fatal("authorized client key should be allowed")
	}
	if node.clientAllowed("ed25519:bb") {
		t.Fatal("unauthorized client key should be rejected")
	}
	if err := registry.SetNodeKeyEnabled("ed25519:aa", false); err != nil {
		t.Fatal(err)
	}
	if node.clientAllowed("ed25519:aa") {
		t.Fatal("disabled client key should be rejected")
	}
}

func TestEnsureClientCertExtractsEmbedded(t *testing.T) {
	if len(embeddedNodeCert) == 0 {
		t.Skip("no embedded certificate")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "certs", "node.crt")
	if err := ensureClientCert(&Settings{Role: "client", TLSCAFile: target}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, embeddedNodeCert) {
		t.Fatal("extracted certificate does not match the embedded one")
	}

	nodeTarget := filepath.Join(dir, "nodecerts", "node.crt")
	if err := ensureClientCert(&Settings{Role: "node", TLSCAFile: nodeTarget}); err != nil {
		t.Fatal(err)
	}
	if fileExists(nodeTarget) {
		t.Fatal("node role must not extract the client certificate")
	}
}

func TestGroupByIdentity(t *testing.T) {
	settings := &Settings{
		IdentityDir: "identity",
		HiddenServices: []HiddenService{
			{Alias: "a", IdentityDir: "id/a", VirtualPort: 80, Target: "127.0.0.1:1"},
			{Alias: "b", IdentityDir: "id/a", VirtualPort: 81, Target: "127.0.0.1:2"},
			{Alias: "c", VirtualPort: 80, Target: "127.0.0.1:3"},
		},
	}
	identities, err := groupByIdentity(settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(identities))
	}
	if identities[0].dir != "id/a" || len(identities[0].declarations) != 2 {
		t.Fatalf("unexpected first identity: %+v", identities[0])
	}
	if identities[1].dir != "identity" || len(identities[1].declarations) != 1 {
		t.Fatalf("unexpected second identity: %+v", identities[1])
	}

	duplicate := &Settings{
		IdentityDir: "identity",
		HiddenServices: []HiddenService{
			{IdentityDir: "id/x", VirtualPort: 80, Target: "127.0.0.1:1"},
			{IdentityDir: "id/x", VirtualPort: 80, Target: "127.0.0.1:2"},
		},
	}
	if _, err := groupByIdentity(duplicate); err == nil {
		t.Fatal("expected duplicate virtual_port error within the same identity_dir")
	}
}

func TestAgentMultipleIdentities(t *testing.T) {
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)

	hiddenA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_A")
	}))
	defer hiddenA.Close()
	hiddenB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_B")
	}))
	defer hiddenB.Close()

	addrA := strings.TrimPrefix(hiddenA.URL, "http://")
	addrB := strings.TrimPrefix(hiddenB.URL, "http://")
	_, portAStr, _ := net.SplitHostPort(addrA)
	_, portBStr, _ := net.SplitHostPort(addrB)
	portA, _ := strconv.Atoi(portAStr)
	portB, _ := strconv.Atoi(portBStr)

	nodeTunnel := freeAddr(t)
	nodeSettings := &Settings{
		Role:                    "node",
		DBName:                  filepath.Join(dir, "node.db"),
		TunnelListen:            nodeTunnel,
		ProxyListen:             "off",
		TLSCertFile:             filepath.Join(dir, "node.crt"),
		TLSKeyFile:              filepath.Join(dir, "node.key"),
		DNServers:               []string{"1.1.1.1:53"},
		HeartbeatSecond:         5,
		HeartbeatTimeoutSeconds: 15,
	}
	nodeSettings.applyDefaults()

	dirA := filepath.Join(dir, "idA")
	dirB := filepath.Join(dir, "idB")
	privA, err := LoadOrCreateKey(filepath.Join(dirA, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	privB, err := LoadOrCreateKey(filepath.Join(dirB, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	nameA := DeriveName(privA.Public().(ed25519.PublicKey))
	nameB := DeriveName(privB.Public().(ed25519.PublicKey))
	if nameA == nameB {
		t.Fatal("distinct identities should derive distinct names")
	}

	agentSettings := &Settings{
		Role:            "agent",
		NodeAddr:        nodeTunnel,
		TLSSkipVerify:   true,
		IdentityDir:     filepath.Join(dir, "identity"),
		HeartbeatSecond: 5,
		HiddenServices: []HiddenService{
			{Alias: "a", IdentityDir: dirA, VirtualPort: portA, Target: addrA},
			{Alias: "b", IdentityDir: dirB, VirtualPort: portB, Target: addrB},
		},
	}

	clientAddr := freeAddr(t)
	clientSettings := &Settings{
		Role:            "client",
		NodeAddr:        nodeTunnel,
		TLSSkipVerify:   true,
		ProxyListen:     clientAddr,
		ClientKeyFile:   filepath.Join(dir, "client.key"),
		HeartbeatSecond: 5,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runNode(ctx, nodeSettings, logger) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = runAgent(ctx, agentSettings, logger) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = runClient(ctx, clientSettings, logger) }()

	assertViaProxy(t, clientAddr, nameA, portA, "SURFACE_A")
	assertViaProxy(t, clientAddr, nameB, portB, "SURFACE_B")
}

func TestCombinedMode(t *testing.T) {
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)

	hidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_HIDDEN")
	}))
	defer hidden.Close()
	internet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "SURFACE_INTERNET")
	}))
	defer internet.Close()

	hiddenAddr := strings.TrimPrefix(hidden.URL, "http://")
	internetAddr := strings.TrimPrefix(internet.URL, "http://")
	_, hiddenPortStr, _ := net.SplitHostPort(hiddenAddr)
	hiddenPort, _ := strconv.Atoi(hiddenPortStr)
	internetHost, internetPortStr, _ := net.SplitHostPort(internetAddr)
	internetPort, _ := strconv.Atoi(internetPortStr)

	nodeTunnel := freeAddr(t)
	nodeSettings := &Settings{
		Role:                    "node",
		DBName:                  filepath.Join(dir, "node.db"),
		TunnelListen:            nodeTunnel,
		ProxyListen:             "off",
		TLSCertFile:             filepath.Join(dir, "node.crt"),
		TLSKeyFile:              filepath.Join(dir, "node.key"),
		DNServers:               []string{"1.1.1.1:53"},
		HeartbeatSecond:         5,
		HeartbeatTimeoutSeconds: 15,
	}
	nodeSettings.applyDefaults()

	identityDir := filepath.Join(dir, "identity")
	priv, err := LoadOrCreateKey(filepath.Join(identityDir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	agentName := DeriveName(priv.Public().(ed25519.PublicKey))

	combinedAddr := freeAddr(t)
	combinedSettings := &Settings{
		Role:            roleCombined,
		NodeAddr:        nodeTunnel,
		TLSSkipVerify:   true,
		ProxyListen:     combinedAddr,
		ClientKeyFile:   filepath.Join(dir, "client.key"),
		IdentityDir:     identityDir,
		HeartbeatSecond: 5,
		HiddenServices:  []HiddenService{{Alias: "hidden", VirtualPort: hiddenPort, Target: hiddenAddr}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runNode(ctx, nodeSettings, logger) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = runCombined(ctx, combinedSettings, logger) }()

	assertViaProxy(t, combinedAddr, agentName, hiddenPort, "SURFACE_HIDDEN")
	assertViaProxy(t, combinedAddr, internetHost, internetPort, "SURFACE_INTERNET")
}
