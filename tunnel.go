package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	connRegister byte = 1
	connRequest  byte = 2

	handshakeTimeout = 15 * time.Second
)

var (
	errAuthFailed = errors.New("authentication failed")
	errRejected   = errors.New("connection rejected")
)

type ServiceDeclaration struct {
	VirtualPort int    `json:"virtual_port"`
	Alias       string `json:"alias"`
}

type Registration struct {
	Name     string               `json:"name"`
	Services []ServiceDeclaration `json:"services"`
	E2E      bool                 `json:"e2e"`
	Protocol int                  `json:"protocol"`
}

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	return cfg
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func peerHandshake(conn net.Conn, priv ed25519.PrivateKey, ctype byte, timeout time.Duration) error {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	msg := append(append([]byte{}, nonce...), ctype)
	sig := ed25519.Sign(priv, msg)

	header := make([]byte, 0, 1+ed25519.PublicKeySize+ed25519.SignatureSize)
	header = append(header, ctype)
	header = append(header, pub...)
	header = append(header, sig...)
	if _, err := conn.Write(header); err != nil {
		return err
	}
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		return err
	}
	if status[0] != 0 {
		return errRejected
	}
	return nil
}

func readPeerHandshake(conn net.Conn, timeout time.Duration) (byte, ed25519.PublicKey, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, err
	}
	if _, err := conn.Write(nonce); err != nil {
		return 0, nil, err
	}
	header := make([]byte, 1+ed25519.PublicKeySize+ed25519.SignatureSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	ctype := header[0]
	pub := ed25519.PublicKey(append([]byte{}, header[1:1+ed25519.PublicKeySize]...))
	sig := header[1+ed25519.PublicKeySize:]
	msg := append(append([]byte{}, nonce...), ctype)
	if !ed25519.Verify(pub, msg, sig) {
		return 0, nil, errAuthFailed
	}
	return ctype, pub, nil
}

func writeStatus(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{code})
	return err
}

func writeRegistration(conn net.Conn, reg Registration) error {
	raw, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = conn.Write(raw)
	return err
}

func readRegistration(conn net.Conn, timeout time.Duration) (*Registration, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > 1<<16 {
		return nil, errors.New("invalid registration size")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, err
	}
	var reg Registration
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func writeRequestHeader(w io.Writer, host string, port int) error {
	host = NormalizeHost(host)
	if len(host) == 0 || len(host) > 255 {
		return errors.New("invalid host length")
	}
	buf := make([]byte, 0, 1+len(host)+2)
	buf = append(buf, byte(len(host)))
	buf = append(buf, host...)
	buf = append(buf, byte(port>>8), byte(port))
	_, err := w.Write(buf)
	return err
}

func readRequestHeader(r io.Reader) (string, int, error) {
	return readHostPort(r)
}

func writeVirtualPort(w io.Writer, port int) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(port))
	_, err := w.Write(b[:])
	return err
}

func readVirtualPort(r io.Reader) (int, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b[:])), nil
}

// dialTLSAddr establishes a TLS connection to a specific node address,
// using the per-node certificate (NodeCAFiles) or the shared one.
func dialTLSAddr(s *Settings, addr string) (net.Conn, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: hostOnly(addr),
	}
	if s.TLSSkipVerify || s.effectiveNodeAuth() == "none" {
		// Zero-trust mode: the node is an untrusted relay. TLS is used only to
		// encrypt the transport; data confidentiality comes from the end-to-end
		// layer between client and agent.
		cfg.InsecureSkipVerify = true
	} else {
		raw, err := trustedNodeCertBytesFor(s, addr)
		if err != nil {
			return nil, err
		}
		certs, err := parseCertificatesPEM(raw)
		if err != nil {
			return nil, err
		}
		pins := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			pins = append(pins, pinnedKeyFingerprint(cert))
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifyPinnedCertificateAny(pins)
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func hostOnly(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return strings.Trim(host, "[]")
	}
	return address
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}
