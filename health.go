package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func startHealthServer(listen string, node *Node, logger *log.Logger) {
	handler := http.NewServeMux()
	handler.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		online, err := node.registry.CountOnlineServices()
		status := "success"
		message := "ok"
		if err != nil {
			status = "error"
			message = err.Error()
		}
		payload := map[string]any{
			"status":  status,
			"message": message,
			"data": map[string]any{
				"services_online": online,
				"agents":          node.sessions.CountByRole("agent"),
				"clients":         node.sessions.CountByRole("client"),
				"time":            time.Now().UTC().Format(time.RFC3339),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	})
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Printf("health server on %s", listen)
	if err := server.ListenAndServe(); err != nil {
		logger.Printf("health server stopped: %v", err)
	}
}
