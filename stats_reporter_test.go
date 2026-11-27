package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestStatsReporterSendAndFallback(t *testing.T) {
	var primaryCalls, fallbackCalls int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryCalls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackCalls, 1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		var sample StatsSample
		if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
			t.Errorf("decode sample: %v", err)
		}
		if sample.NodeID == "" || sample.Sig == "" || sample.SessionID == "" {
			t.Errorf("incomplete sample: %+v", sample)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"observed_ip":"198.51.100.7","ip_source":"observed"}`)
	}))
	defer fallback.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	meter := NewTrafficMeter()
	meter.Add(TrafficSurface, true, 10)
	meter.Add(TrafficSurface, false, 20)
	node := &Node{stats: meter}
	settings := &Settings{
		StatsEnabled:         true,
		StatsNickname:        "alice",
		StatsURLs:            []string{primary.URL, fallback.URL},
		StatsIntervalSeconds: 60,
	}
	reporter := NewStatsReporter(node, settings, log.New(io.Discard, "", 0), priv)
	if err := reporter.send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&primaryCalls) != 1 || atomic.LoadInt32(&fallbackCalls) != 1 {
		t.Fatalf("unexpected calls primary=%d fallback=%d", primaryCalls, fallbackCalls)
	}
	if reporter.lastObservedIP != "198.51.100.7" {
		t.Fatalf("observed IP = %q", reporter.lastObservedIP)
	}
	if reporter.seq != 1 {
		t.Fatalf("seq = %d", reporter.seq)
	}
}
