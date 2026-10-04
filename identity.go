package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const surfaceSuffix = ".surface"

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		switch len(raw) {
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(raw), nil
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(raw), nil
		default:
			return nil, fmt.Errorf("invalid key length in %s", path)
		}
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func PublicKeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + hex.EncodeToString(pub)
}

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "ed25519:")
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func DeriveName(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	id := strings.ToLower(base32NoPad.EncodeToString(sum[:10]))
	return id + surfaceSuffix
}

func WriteHostname(dir, name string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "hostname"), []byte(name+"\n"), 0o644)
}

func IsSurfaceName(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), surfaceSuffix)
}

func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
