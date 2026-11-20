package main

import (
	"context"
	"log"
	"sync"
)

func runCombined(ctx context.Context, s *Settings, logger *log.Logger) error {
	if err := ensureClientCert(s); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	discovery, err := NewPeerDiscovery(s, logger)
	if err != nil {
		return err
	}
	if discovery != nil {
		go discovery.Run(ctx)
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- runClientWithDiscovery(ctx, s, logger, discovery)
	}()

	if len(s.HiddenServices) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- runAgentWithDiscovery(ctx, s, logger, discovery)
		}()
	} else {
		logger.Printf("combined mode: no hidden_services configured, running client only")
	}

	err = <-errCh
	cancel()
	wg.Wait()
	return err
}
