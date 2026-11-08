package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"time"
)

func runClient(ctx context.Context, s *Settings, logger *log.Logger) error {
	if err := ensureClientCert(s); err != nil {
		return err
	}
	priv, err := LoadOrCreateKey(s.ClientKeyFile)
	if err != nil {
		return err
	}
	logger.Printf("client public key: %s", PublicKeyString(priv.Public().(ed25519.PublicKey)))
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if err := clientSession(ctx, s, logger, priv); err != nil {
			logger.Printf("client session ended: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}

func clientSession(ctx context.Context, s *Settings, logger *log.Logger, priv ed25519.PrivateKey) error {
	if len(s.effectiveNodeAddrs()) == 0 {
		return errors.New("client requires node_addr or node_addrs")
	}

	dialer := NewMultiNodeDialer(s, priv, logger)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialerDone := make(chan struct{})
	go func() {
		defer close(dialerDone)
		dialer.Run(sessionCtx)
	}()

	proxy := NewProxyServer(s.ProxyListen, dialer, logger)
	err := proxy.Start(sessionCtx)
	cancel()
	<-dialerDone
	return err
}
