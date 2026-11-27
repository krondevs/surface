package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestTrafficMeter(t *testing.T) {
	meter := NewTrafficMeter()
	meter.Add(TrafficSurface, true, 100)
	meter.Add(TrafficSurface, false, 200)
	meter.Add(TrafficExit, true, 300)
	meter.Add(TrafficExit, false, 400)

	got := meter.Snapshot()
	if got.Ingress != 400 || got.Egress != 600 {
		t.Fatalf("unexpected totals: %+v", got)
	}
	if got.SurfaceIngress != 100 || got.SurfaceEgress != 200 || got.Surface() != 300 {
		t.Fatalf("unexpected surface counters: %+v", got)
	}
	if got.ExitIngress != 300 || got.ExitEgress != 400 || got.Exit() != 700 {
		t.Fatalf("unexpected exit counters: %+v", got)
	}
	if got.Total() != 1000 {
		t.Fatalf("unexpected total: %d", got.Total())
	}
}

func TestPipeMetered(t *testing.T) {
	clientSide, clientPeer := net.Pipe()
	upstreamSide, upstreamPeer := net.Pipe()
	meter := NewTrafficMeter()
	done := make(chan struct{})
	go func() {
		pipeMetered(clientSide, upstreamSide, meter, TrafficSurface)
		close(done)
	}()

	go func() { _, _ = clientPeer.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(upstreamPeer, buf); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = upstreamPeer.Write([]byte("world")) }()
	if _, err := io.ReadFull(clientPeer, buf); err != nil {
		t.Fatal(err)
	}
	clientPeer.Close()
	upstreamPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeMetered did not stop")
	}

	got := meter.Snapshot()
	if got.Ingress != 5 || got.Egress != 5 {
		t.Fatalf("unexpected metered bytes: %+v", got)
	}
	if got.SurfaceIngress != 5 || got.SurfaceEgress != 5 {
		t.Fatalf("unexpected surface bytes: %+v", got)
	}
}

func TestSignStatsSample(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sample := StatsSample{
		V:               1,
		NodeID:          PublicKeyString(priv.Public().(ed25519.PublicKey)),
		Nickname:        "alice",
		AdvertiseAddr:   "203.0.113.10:9253",
		SessionID:       "session",
		Seq:             1,
		SentAt:          "2026-11-27T10:00:00Z",
		IntervalSeconds: 60,
		UptimeSeconds:   10,
		Counters:        TrafficCounters{Ingress: 1, Egress: 2},
	}
	if err := signStatsSample(priv, &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Sig == "" {
		t.Fatal("missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(sample.Sig)
	if err != nil {
		t.Fatal(err)
	}
	clone := sample
	clone.Sig = ""
	raw, err := json.Marshal(&clone)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), raw, sig) {
		t.Fatal("signature did not verify")
	}
}

func TestSanitizeNickname(t *testing.T) {
	tests := map[string]string{
		"  Alice Node  ": "Alice-Node",
		"nodo-1":         "nodo-1",
		"<script>":       "script",
		"ab":             "",
		"":               "",
	}
	for input, want := range tests {
		if got := sanitizeNickname(input); got != want {
			t.Fatalf("sanitizeNickname(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHostFromAdvertise(t *testing.T) {
	if got := hostFromAdvertise("203.0.113.10:9253"); got != "203.0.113.10" {
		t.Fatalf("hostFromAdvertise = %q", got)
	}
	if got := hostFromAdvertise("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("hostFromAdvertise = %q", got)
	}
}
