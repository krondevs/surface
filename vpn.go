package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// runVpn runs the client (SOCKS5 proxy) and tun2socks (TUN -> SOCKS5) in the
// same process. The TUN file descriptor is inherited from the Android
// VpnService and passed in via --tun-fd.
func runVpn(ctx context.Context, s *Settings, logger *log.Logger, tunFd int) error {
	if err := ensureClientCert(s); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	// SOCKS5 proxy (client role).
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- runClient(ctx, s, logger)
	}()

	// tun2socks: forward TUN traffic to the local SOCKS5 proxy.
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- runTun2socks(ctx, s, tunFd)
	}()

	err := <-errCh
	cancel()
	wg.Wait()
	return err
}

func runTun2socks(ctx context.Context, s *Settings, tunFd int) error {
	key := &engine.Key{
		Device:   fmt.Sprintf("fd://%d", tunFd),
		Proxy:    fmt.Sprintf("socks5://%s", s.ProxyListen),
		MTU:      1500,
		LogLevel: "warn",
	}
	engine.Insert(key)
	engine.Start()
	defer engine.Stop()

	<-ctx.Done()
	return nil
}
