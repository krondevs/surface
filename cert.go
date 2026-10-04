package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func parseCertificatePEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func pinnedKeyFingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func verifyPinnedCertificate(pinned []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], pinned) != 1 {
			return errors.New("node public key does not match the pinned key")
		}
		return nil
	}
}

func trustedNodeCertBytes(s *Settings) ([]byte, error) {
	if s.TLSCAFile != "" {
		if raw, err := os.ReadFile(s.TLSCAFile); err == nil {
			return raw, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if len(embeddedNodeCert) > 0 {
		return embeddedNodeCert, nil
	}
	return nil, errors.New("no trusted node certificate available")
}

func ensureClientCert(s *Settings) error {
	if s.Role != "client" && s.Role != "agent" && s.Role != roleCombined {
		return nil
	}
	if s.TLSCAFile == "" || fileExists(s.TLSCAFile) {
		return nil
	}
	if len(embeddedNodeCert) == 0 {
		return fmt.Errorf("tls_ca_file %q not found and no embedded certificate", s.TLSCAFile)
	}
	if dir := filepath.Dir(s.TLSCAFile); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(s.TLSCAFile, embeddedNodeCert, 0o644)
}
