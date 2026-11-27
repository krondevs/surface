package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"time"
)

func runClient(ctx context.Context, s *Settings, logger *log.Logger) error {
	discovery, err := NewPeerDiscovery(s, logger)
	if err != nil {
		return err
	}
	if discovery != nil {
		go discovery.Run(ctx)
	}
	return runClientWithDiscovery(ctx, s, logger, discovery)
}

func runClientWithDiscovery(ctx context.Context, s *Settings, logger *log.Logger, discovery *PeerDiscovery) error {
	if err := ensureClientCert(s); err != nil {
		return err
	}
	priv, err := LoadOrCreateKey(s.ClientKeyFile)
	if err != nil {
		return err
	}
	logger.Printf("client public key: %s", PublicKeyString(priv.Public().(ed25519.PublicKey)))
	if len(s.effectiveNodeAddrs()) == 0 {
		return errors.New("client requires node_addr or node_addrs")
	}

	dialer := NewMultiNodeDialer(s, priv, logger)
	if discovery != nil {
		for _, peer := range discovery.Snapshot() {
			dialer.AddInitialPeer(peer.Address)
		}
		discovery.Subscribe(func(peer PeerInfo) {
			dialer.AddPeer(peer.Address)
		})
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	dialerDone := make(chan struct{})
	go func() {
		defer close(dialerDone)
		dialer.Run(sessionCtx)
	}()

	for {
		proxy := NewProxyServer(s.ProxyListen, dialer, logger, nil)
		err := proxy.Start(sessionCtx)
		if ctx.Err() != nil {
			break
		}
		logger.Printf("client session ended: %v", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	cancel()
	<-dialerDone
	return nil
}
