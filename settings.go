package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type HiddenService struct {
	Alias       string `json:"alias"`
	IdentityDir string `json:"identity_dir"`
	VirtualPort int    `json:"virtual_port"`
	Target      string `json:"target"`
}

type Settings struct {
	Role    string `json:"role"`
	DBName  string `json:"db_name"`
	LogFile string `json:"log_file"`

	TunnelListen            string   `json:"tunnel_listen"`
	ProxyListen             string   `json:"proxy_listen"`
	HealthListen            string   `json:"health_listen"`
	ExitProxy               string   `json:"exit_proxy"`
	ExitProxyFallbackDirect bool     `json:"exit_proxy_fallback_direct"`
	TLSCertFile             string   `json:"tls_cert_file"`
	TLSKeyFile              string   `json:"tls_key_file"`
	DNServers               []string `json:"dns_servers"`
	HeartbeatTimeoutSeconds int      `json:"heartbeat_timeout_seconds"`
	AllowedAgents           []string `json:"allowed_agents"`

	NodeAddr        string            `json:"node_addr"`
	NodeAddrs       []string          `json:"node_addrs"`
	NodeStrategy    string            `json:"node_strategy"`
	NodeCAFiles     map[string]string `json:"node_ca_files"`
	TLSCAFile       string            `json:"tls_ca_file"`
	TLSSkipVerify   bool              `json:"tls_skip_verify"`
	IdentityDir     string            `json:"identity_dir"`
	HiddenServices  []HiddenService   `json:"hidden_services"`
	HeartbeatSecond int               `json:"heartbeat_seconds"`
	ClientKeyFile   string            `json:"client_key_file"`
	Aliases         map[string]string `json:"aliases"`
}

func defaultSettings() *Settings {
	return &Settings{
		Role:                    "node",
		DBName:                  "surface.db",
		LogFile:                 "surface.log",
		TunnelListen:            "0.0.0.0:9253",
		ProxyListen:             "127.0.0.1:9252",
		TLSCertFile:             "certs/node.crt",
		TLSKeyFile:              "certs/node.key",
		DNServers:               []string{"1.1.1.1:53", "8.8.8.8:53"},
		HeartbeatTimeoutSeconds: 45,
		IdentityDir:             "identity",
		HeartbeatSecond:         15,
		ClientKeyFile:           "keys/client.key",
		Aliases:                 map[string]string{},
	}
}

func (s *Settings) applyDefaults() {
	d := defaultSettings()
	if s.Role == "" {
		s.Role = d.Role
	}
	if s.DBName == "" {
		s.DBName = d.DBName
	}
	if s.LogFile == "" {
		s.LogFile = d.LogFile
	}
	if s.TunnelListen == "" {
		s.TunnelListen = d.TunnelListen
	}
	if s.ProxyListen == "" {
		s.ProxyListen = d.ProxyListen
	}
	if s.TLSCertFile == "" {
		s.TLSCertFile = d.TLSCertFile
	}
	if s.TLSKeyFile == "" {
		s.TLSKeyFile = d.TLSKeyFile
	}
	if len(s.DNServers) == 0 {
		s.DNServers = d.DNServers
	}
	if s.HeartbeatTimeoutSeconds <= 0 {
		s.HeartbeatTimeoutSeconds = d.HeartbeatTimeoutSeconds
	}
	if s.IdentityDir == "" {
		s.IdentityDir = d.IdentityDir
	}
	if s.HeartbeatSecond <= 0 {
		s.HeartbeatSecond = d.HeartbeatSecond
	}
	if s.ClientKeyFile == "" {
		s.ClientKeyFile = d.ClientKeyFile
	}
	if s.Aliases == nil {
		s.Aliases = map[string]string{}
	}
}

func LoadSettings(path string) (*Settings, error) {
	if path == "" {
		return nil, errors.New("config path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := defaultSettings()
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	s.applyDefaults()
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// effectiveNodeAddrs returns the list of node addresses to connect to.
// NodeAddrs takes precedence over NodeAddr for backwards compatibility.
func (s *Settings) effectiveNodeAddrs() []string {
	if len(s.NodeAddrs) > 0 {
		out := make([]string, 0, len(s.NodeAddrs))
		for _, addr := range s.NodeAddrs {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				out = append(out, addr)
			}
		}
		return out
	}
	if s.NodeAddr != "" {
		return []string{s.NodeAddr}
	}
	return nil
}

// effectiveNodeStrategy returns the normalized strategy name.
func (s *Settings) effectiveNodeStrategy() string {
	switch strings.ToLower(strings.TrimSpace(s.NodeStrategy)) {
	case "latency":
		return "latency"
	case "random":
		return "random"
	case "", "round_robin":
		return "round_robin"
	default:
		return "round_robin"
	}
}

// validate checks for configuration errors.
func (s *Settings) validate() error {
	strategy := strings.ToLower(strings.TrimSpace(s.NodeStrategy))
	switch strategy {
	case "", "round_robin", "latency", "random":
		// ok
	default:
		return fmt.Errorf("unknown node_strategy %q (use round_robin, latency, or random)", s.NodeStrategy)
	}
	return nil
}
