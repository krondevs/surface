package main

import (
	"io"
	"net"
	"sync/atomic"
)

// TrafficClass identifies which kind of traffic a relayed byte belongs to.
type TrafficClass uint8

const (
	TrafficSurface TrafficClass = iota
	TrafficExit
)

// TrafficCounters is the wire and snapshot representation of relayed payload
// bytes. Ingress is client -> node -> upstream; Egress is the reverse path.
type TrafficCounters struct {
	Ingress        uint64 `json:"ingress"`
	Egress         uint64 `json:"egress"`
	SurfaceIngress uint64 `json:"surface_ingress"`
	SurfaceEgress  uint64 `json:"surface_egress"`
	ExitIngress    uint64 `json:"exit_ingress"`
	ExitEgress     uint64 `json:"exit_egress"`
}

func (c TrafficCounters) Total() uint64 {
	return c.Ingress + c.Egress
}

func (c TrafficCounters) Surface() uint64 {
	return c.SurfaceIngress + c.SurfaceEgress
}

func (c TrafficCounters) Exit() uint64 {
	return c.ExitIngress + c.ExitEgress
}

// TrafficMeter accumulates relayed payload bytes without holding a lock on the
// data path. A nil meter is safe and is used for roles that do not report.
type TrafficMeter struct {
	ingress        atomic.Uint64
	egress         atomic.Uint64
	surfaceIngress atomic.Uint64
	surfaceEgress  atomic.Uint64
	exitIngress    atomic.Uint64
	exitEgress     atomic.Uint64
}

func NewTrafficMeter() *TrafficMeter {
	return &TrafficMeter{}
}

func (m *TrafficMeter) Add(class TrafficClass, ingress bool, n int64) {
	if m == nil || n <= 0 {
		return
	}
	v := uint64(n)
	if ingress {
		m.ingress.Add(v)
		if class == TrafficSurface {
			m.surfaceIngress.Add(v)
		} else {
			m.exitIngress.Add(v)
		}
		return
	}
	m.egress.Add(v)
	if class == TrafficSurface {
		m.surfaceEgress.Add(v)
	} else {
		m.exitEgress.Add(v)
	}
}

func (m *TrafficMeter) Snapshot() TrafficCounters {
	if m == nil {
		return TrafficCounters{}
	}
	return TrafficCounters{
		Ingress:        m.ingress.Load(),
		Egress:         m.egress.Load(),
		SurfaceIngress: m.surfaceIngress.Load(),
		SurfaceEgress:  m.surfaceEgress.Load(),
		ExitIngress:    m.exitIngress.Load(),
		ExitEgress:     m.exitEgress.Load(),
	}
}

func trafficClassForHost(host string) TrafficClass {
	if IsSurfaceName(host) {
		return TrafficSurface
	}
	return TrafficExit
}

// pipeMetered is the metered equivalent of pipe. The byte counters are updated
// once per direction, so a relayed payload is never counted twice.
func pipeMetered(a, b net.Conn, meter *TrafficMeter, class TrafficClass) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(a, b)
		meter.Add(class, false, n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(b, a)
		meter.Add(class, true, n)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}

// countingWriter is used for one-shot HTTP proxy requests where the request is
// written before the response is copied back.
type countingWriter struct {
	w     io.Writer
	meter *TrafficMeter
	class TrafficClass
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.meter.Add(c.class, true, int64(n))
	}
	return n, err
}
