package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type recordingProxy struct {
	name string
	err  error

	mu    sync.Mutex
	calls []string
}

func (p *recordingProxy) DialTarget(_ context.Context, host string, port int) (net.Conn, error) {
	p.mu.Lock()
	p.calls = append(p.calls, net.JoinHostPort(host, strconv.Itoa(port)))
	p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func (p *recordingProxy) String() string { return p.name }

func (p *recordingProxy) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func TestIsOnionName(t *testing.T) {
	cases := map[string]bool{
		"abc.onion":         true,
		"ABC.ONION.":        true,
		"sub.abc.onion":     true,
		"abc.surface":       false,
		"onion":             false,
		"abc.onion.surface": false,
		"example.com":       false,
		"":                  false,
	}
	for host, want := range cases {
		if got := IsOnionName(host); got != want {
			t.Errorf("IsOnionName(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParseOnionProxy(t *testing.T) {
	for _, raw := range []string{"", "off", "none", "disabled"} {
		d, err := parseOnionProxy(raw)
		if err != nil || d != nil {
			t.Fatalf("parseOnionProxy(%q) = %v, %v; want nil, nil", raw, d, err)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"socks5://127.0.0.1:9050", "socks5://127.0.0.1:9050"},
		{"127.0.0.1:9050", "socks5://127.0.0.1:9050"},
		{"socks5h://127.0.0.1:9050", "socks5://127.0.0.1:9050"},
	} {
		d, err := parseOnionProxy(c.in)
		if err != nil {
			t.Fatalf("parseOnionProxy(%q): %v", c.in, err)
		}
		if d.String() != c.want {
			t.Fatalf("parseOnionProxy(%q) = %q, want %q", c.in, d.String(), c.want)
		}
	}
	for _, bad := range []string{"http://127.0.0.1:8080", "ftp://127.0.0.1:21", "socks5://127.0.0.1"} {
		if _, err := parseOnionProxy(bad); err == nil {
			t.Fatalf("parseOnionProxy(%q) should fail", bad)
		}
	}
}

func TestSocks5OnionSendsHostnameToProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		if request[3] != 0x03 {
			got <- ""
			return
		}
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, host); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			return
		}
		got <- string(host)
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	}()

	d := &socks5Dialer{addr: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.DialTarget(ctx, "abc.onion", 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	select {
	case host := <-got:
		if host != "abc.onion" {
			t.Fatalf("proxy received host %q, want abc.onion", host)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SOCKS5 request")
	}
}

func TestInternetDialerRoutesOnionOnlyToTor(t *testing.T) {
	onion := &recordingProxy{name: "tor"}
	clearnet := &recordingProxy{name: "exit"}
	d := &InternetDialer{
		onionProxy: onion,
		proxy:      clearnet,
		logger:     log.New(io.Discard, "", 0),
	}

	conn, err := d.DialTarget("ABC.ONION.", 80)
	if err != nil {
		t.Fatalf("onion dial: %v", err)
	}
	conn.Close()
	if got := onion.snapshot(); len(got) != 1 || got[0] != "abc.onion:80" {
		t.Fatalf("onion calls = %v, want [abc.onion:80]", got)
	}
	if got := clearnet.snapshot(); len(got) != 0 {
		t.Fatalf("clearnet calls = %v, want none", got)
	}

	conn, err = d.DialTarget("Example.COM.", 443)
	if err != nil {
		t.Fatalf("clearnet dial: %v", err)
	}
	conn.Close()
	if got := clearnet.snapshot(); len(got) != 1 || got[0] != "example.com:443" {
		t.Fatalf("clearnet calls = %v, want [example.com:443]", got)
	}
	if got := onion.snapshot(); len(got) != 1 {
		t.Fatalf("onion calls = %v, want only the previous one", got)
	}
}

func TestInternetDialerOnionRequiresProxy(t *testing.T) {
	clearnet := &recordingProxy{name: "exit"}
	d := &InternetDialer{
		proxy:  clearnet,
		logger: log.New(io.Discard, "", 0),
	}
	if _, err := d.DialTarget("x.onion", 80); !errors.Is(err, errOnionProxyRequired) {
		t.Fatalf("err = %v, want %v", err, errOnionProxyRequired)
	}
	if got := clearnet.snapshot(); len(got) != 0 {
		t.Fatalf("clearnet calls = %v, want none", got)
	}
}

func TestInternetDialerOnionDoesNotFallbackToClearnet(t *testing.T) {
	torErr := errors.New("tor down")
	onion := &recordingProxy{name: "tor", err: torErr}
	clearnet := &recordingProxy{name: "exit"}
	d := &InternetDialer{
		onionProxy: onion,
		proxy:      clearnet,
		fallback:   true,
		logger:     log.New(io.Discard, "", 0),
	}
	if _, err := d.DialTarget("x.onion", 80); !errors.Is(err, torErr) {
		t.Fatalf("err = %v, want %v", err, torErr)
	}
	if got := clearnet.snapshot(); len(got) != 0 {
		t.Fatalf("clearnet calls = %v, want none", got)
	}
}

func TestGeneratedSettingsDefaults(t *testing.T) {
	var s Settings
	if err := json.Unmarshal(defaultSettingsJSON, &s); err != nil {
		t.Fatalf("embedded settings: %v", err)
	}
	if !s.TLSSkipVerify {
		t.Fatal("generated settings should set tls_skip_verify=true")
	}
	if s.NodeAuth != "none" {
		t.Fatalf("generated node_auth = %q, want none", s.NodeAuth)
	}
	if s.OnionProxy != "socks5://127.0.0.1:9050" {
		t.Fatalf("generated onion_proxy = %q", s.OnionProxy)
	}
	if !s.PeerDiscovery {
		t.Fatal("generated settings should enable peer_discovery")
	}
	if len(s.SeedNodes) != 3 {
		t.Fatalf("generated seed_nodes = %v", s.SeedNodes)
	}
	if s.NodeKeyFile == "" || s.PeerKeyFile == "" || s.PeerCacheFile == "" {
		t.Fatal("generated settings should include node/peer key and cache paths")
	}
	if len(s.HiddenServices) != 1 || s.HiddenServices[0].Alias != "apix24" {
		t.Fatalf("generated hidden_services = %+v, want the apix24 example", s.HiddenServices)
	}
}

func TestDefaultOnionProxy(t *testing.T) {
	if got := defaultSettings().OnionProxy; got != "socks5://127.0.0.1:9050" {
		t.Fatalf("default onion_proxy = %q", got)
	}
	s := &Settings{}
	s.applyDefaults()
	if got := s.OnionProxy; got != "socks5://127.0.0.1:9050" {
		t.Fatalf("applied onion_proxy = %q", got)
	}
}

func TestValidateOnionProxy(t *testing.T) {
	s := defaultSettings()
	s.OnionProxy = "http://127.0.0.1:8080"
	if err := s.validate(); err == nil {
		t.Fatal("http onion_proxy should fail validation")
	}
	s.OnionProxy = "off"
	if err := s.validate(); err != nil {
		t.Fatalf("off onion_proxy should validate: %v", err)
	}
}
