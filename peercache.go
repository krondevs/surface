package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type peerCacheFile struct {
	Version int        `json:"version"`
	Peers   []PeerInfo `json:"peers"`
}

func loadPeerCache(path string, max int, allowPrivate bool) []PeerInfo {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var payload peerCacheFile
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	if payload.Version != 1 {
		return nil
	}
	now := time.Now()
	seenAddr := map[string]bool{}
	seenKey := map[string]bool{}
	out := make([]PeerInfo, 0, len(payload.Peers))
	for _, peer := range payload.Peers {
		addr, err := normalizePeerAddr(peer.Address, allowPrivate)
		if err != nil {
			continue
		}
		if seenAddr[addr] {
			continue
		}
		if peer.PublicKey != "" {
			if _, err := ParsePublicKey(peer.PublicKey); err != nil {
				continue
			}
			if seenKey[peer.PublicKey] {
				continue
			}
			seenKey[peer.PublicKey] = true
		}
		if !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerTTL {
			continue
		}
		peer.Address = addr
		out = append(out, peer)
		seenAddr[addr] = true
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func savePeerCache(path string, peers []PeerInfo) error {
	if path == "" {
		return nil
	}
	if len(peers) > peerListMax {
		peers = peers[:peerListMax]
	}
	payload := peerCacheFile{Version: 1, Peers: peers}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".peers-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
