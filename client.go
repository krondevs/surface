package main

import (
	"context"
	"crypto/ed25519"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type TunnelDialer struct {
	mux     *yamux.Session
	aliases map[string]string
}

func (t *TunnelDialer) DialTarget(host string, port int) (net.Conn, error) {
	target := NormalizeHost(host)
	if mapped, ok := t.aliases[target]; ok {
		target = NormalizeHost(mapped)
	}
	stream, err := t.mux.Open()
	if err != nil {
		return nil, err
	}
	if err := writeRequestHeader(stream, target, port); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

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
	conn, err := dialTLS(s)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := peerHandshake(conn, priv, connRequest, handshakeTimeout); err != nil {
		return err
	}
	mux, err := yamux.Client(conn, yamuxConfig())
	if err != nil {
		return err
	}
	logger.Printf("connected to node %s", s.NodeAddr)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-mux.CloseChan()
		cancel()
	}()

	dialer := &TunnelDialer{mux: mux, aliases: s.Aliases}
	proxy := NewProxyServer(s.ProxyListen, dialer, logger)
	return proxy.Start(sessionCtx)
}
