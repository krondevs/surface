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

// parseCertificatesPEM decodes all CERTIFICATE blocks in a PEM bundle.
func parseCertificatesPEM(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in pem")
	}
	return certs, nil
}

func pinnedKeyFingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func verifyPinnedCertificate(pinned []byte) func([][]byte, [][]*x509.Certificate) error {
	return verifyPinnedCertificateAny([][]byte{pinned})
}

// verifyPinnedCertificateAny returns a TLS verification function that accepts
// a peer certificate matching any of the provided pinned fingerprints.
func verifyPinnedCertificateAny(pins [][]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		for _, pinned := range pins {
			if subtle.ConstantTimeCompare(sum[:], pinned) == 1 {
				return nil
			}
		}
		return errors.New("node public key does not match any pinned key")
	}
}

// embeddedTrustedCertBytes returns the embedded trust bundle, falling back to
// the single embedded node certificate for older builds.
func embeddedTrustedCertBytes() []byte {
	if len(embeddedNodeCerts) > 0 {
		return embeddedNodeCerts
	}
	return embeddedNodeCert
}

func trustedNodeCertBytes(s *Settings) ([]byte, error) {
	if s.TLSCAFile != "" {
		if raw, err := os.ReadFile(s.TLSCAFile); err == nil {
			return raw, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if raw := embeddedTrustedCertBytes(); len(raw) > 0 {
		return raw, nil
	}
	return nil, errors.New("no trusted node certificate available")
}

// trustedNodeCertBytesFor returns the PEM bytes for a specific node address.
// It checks NodeCAFiles[addr] first, then falls back to the shared TLSCAFile or embedded cert.
func trustedNodeCertBytesFor(s *Settings, addr string) ([]byte, error) {
	if s.NodeCAFiles != nil {
		if file := s.NodeCAFiles[addr]; file != "" {
			raw, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			return raw, nil
		}
	}
	return trustedNodeCertBytes(s)
}

func ensureClientCert(s *Settings) error {
	if s.Role != "client" && s.Role != "agent" && s.Role != roleCombined {
		return nil
	}
	if s.effectiveNodeAuth() == "none" {
		return nil
	}
	if s.TLSCAFile == "" || fileExists(s.TLSCAFile) {
		return nil
	}
	raw := embeddedTrustedCertBytes()
	if len(raw) == 0 {
		return fmt.Errorf("tls_ca_file %q not found and no embedded certificate", s.TLSCAFile)
	}
	if dir := filepath.Dir(s.TLSCAFile); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(s.TLSCAFile, raw, 0o644)
}
