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

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- runClient(ctx, s, logger)
	}()

	if len(s.HiddenServices) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- runAgent(ctx, s, logger)
		}()
	} else {
		logger.Printf("combined mode: no hidden_services configured, running client only")
	}

	err := <-errCh
	cancel()
	wg.Wait()
	return err
}
