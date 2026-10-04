package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type agentIdentity struct {
	dir          string
	name         string
	priv         ed25519.PrivateKey
	targets      map[int]string
	declarations []ServiceDeclaration
}

func groupByIdentity(s *Settings) ([]*agentIdentity, error) {
	order := []string{}
	byDir := map[string]*agentIdentity{}
	for _, service := range s.HiddenServices {
		if service.VirtualPort <= 0 || service.Target == "" {
			return nil, errors.New("hidden service requires virtual_port and target")
		}
		dir := service.IdentityDir
		if dir == "" {
			dir = s.IdentityDir
		}
		identity, ok := byDir[dir]
		if !ok {
			identity = &agentIdentity{dir: dir, targets: map[int]string{}}
			byDir[dir] = identity
			order = append(order, dir)
		}
		if existing, dup := identity.targets[service.VirtualPort]; dup {
			return nil, fmt.Errorf("duplicate virtual_port %d in identity_dir %q (%s and %s)",
				service.VirtualPort, dir, existing, service.Target)
		}
		identity.targets[service.VirtualPort] = service.Target
		identity.declarations = append(identity.declarations, ServiceDeclaration{
			VirtualPort: service.VirtualPort,
			Alias:       service.Alias,
		})
	}
	identities := make([]*agentIdentity, 0, len(order))
	for _, dir := range order {
		identities = append(identities, byDir[dir])
	}
	return identities, nil
}

func runAgent(ctx context.Context, s *Settings, logger *log.Logger) error {
	if err := ensureClientCert(s); err != nil {
		return err
	}
	if len(s.HiddenServices) == 0 {
		return errNoServices()
	}
	identities, err := groupByIdentity(s)
	if err != nil {
		return err
	}
	for _, identity := range identities {
		priv, err := LoadOrCreateKey(filepath.Join(identity.dir, "secret.key"))
		if err != nil {
			return err
		}
		identity.priv = priv
		identity.name = DeriveName(priv.Public().(ed25519.PublicKey))
		if err := WriteHostname(identity.dir, identity.name); err != nil {
			return err
		}
		logger.Printf("identity %s -> %s (%d service(s))", identity.dir, identity.name, len(identity.declarations))
		checkTargets(logger, identity)
	}

	var wg sync.WaitGroup
	for _, identity := range identities {
		wg.Add(1)
		go func(identity *agentIdentity) {
			defer wg.Done()
			runAgentIdentity(ctx, s, logger, identity)
		}(identity)
	}
	wg.Wait()
	return nil
}

func runAgentIdentity(ctx context.Context, s *Settings, logger *log.Logger, identity *agentIdentity) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := agentSession(ctx, s, logger, identity.priv, identity.name, identity.declarations, identity.targets); err != nil {
			logger.Printf("agent[%s] session ended: %v", identity.name, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func checkTargets(logger *log.Logger, identity *agentIdentity) {
	for port, target := range identity.targets {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			logger.Printf("agent[%s] target unreachable vport=%d -> %s: %v", identity.name, port, target, err)
			continue
		}
		conn.Close()
	}
}

func agentSession(ctx context.Context, s *Settings, logger *log.Logger, priv ed25519.PrivateKey, name string, declarations []ServiceDeclaration, targets map[int]string) error {
	conn, err := dialTLS(s)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := peerHandshake(conn, priv, connRegister, handshakeTimeout); err != nil {
		return err
	}
	if err := writeRegistration(conn, Registration{Name: name, Services: declarations}); err != nil {
		return err
	}
	mux, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		return err
	}
	logger.Printf("registered %s with %d service(s)", name, len(declarations))

	go func() {
		<-ctx.Done()
		mux.Close()
	}()

	for {
		stream, err := mux.Accept()
		if err != nil {
			return err
		}
		go agentServeStream(stream, targets)
	}
}

func agentServeStream(stream net.Conn, targets map[int]string) {
	defer stream.Close()
	port, err := readVirtualPort(stream)
	if err != nil {
		return
	}
	target, ok := targets[port]
	if !ok {
		return
	}
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	pipe(stream, conn)
}
