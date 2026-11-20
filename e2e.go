package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"

	"filippo.io/edwards25519"
	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const (
	e2eMaxFrame = noise.MaxMsgLen + 16
	e2eChunk    = 32 * 1024
)

// ed25519PrivateToX25519 derives the X25519 private key from an ed25519 key.
// It uses the same deterministic conversion as libsodium
// (crypto_sign_ed25519_sk_to_curve25519): SHA-512 over the 32-byte seed, with
// the first half used as the X25519 scalar (X25519 clamps it internally).
func ed25519PrivateToX25519(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	sum := sha512.Sum512(priv.Seed())
	out := make([]byte, 32)
	copy(out, sum[:32])
	return out, nil
}

// ed25519PublicToX25519 converts an ed25519 public key to its X25519
// (Montgomery) form.
func ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func x25519Public(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("invalid x25519 private key")
	}
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// e2ePrologue binds the encrypted stream to the service name, port and agent
// key. A malicious relay that redirects the stream elsewhere causes a
// handshake mismatch.
func e2ePrologue(name string, port int, pub ed25519.PublicKey) []byte {
	return []byte("surface-e2e-v1|" + NormalizeHost(name) + "|" +
		strconv.Itoa(port) + "|" + hex.EncodeToString(pub))
}

func noiseCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) > e2eMaxFrame {
		return errors.New("e2e frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > e2eMaxFrame {
		return nil, errors.New("invalid e2e frame size")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// noiseConn wraps a net.Conn with Noise transport encryption. Each Write is
// split into AEAD frames; Read decrypts them into an internal buffer.
type noiseConn struct {
	net.Conn
	send *noise.CipherState
	recv *noise.CipherState
	rbuf []byte
}

func newNoiseConn(conn net.Conn, initiator bool, cs0, cs1 *noise.CipherState) net.Conn {
	send, recv := cs0, cs1
	if !initiator {
		send, recv = cs1, cs0
	}
	return &noiseConn{Conn: conn, send: send, recv: recv}
}

func (c *noiseConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > e2eChunk {
			n = e2eChunk
		}
		ct, err := c.send.Encrypt(nil, nil, p[:n])
		if err != nil {
			return written, err
		}
		if err := writeFrame(c.Conn, ct); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *noiseConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		ct, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		pt, err := c.recv.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, err
		}
		c.rbuf = pt
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// dialE2E runs the Noise NK initiator handshake with the agent and returns an
// encrypted connection. The agent's ed25519 public key must already be
// verified against the .surface name by the caller.
func dialE2E(conn net.Conn, pub ed25519.PublicKey, name string, port int) (net.Conn, error) {
	xPub, err := ed25519PublicToX25519(pub)
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseCipherSuite(),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  xPub,
		Prologue:    e2ePrologue(name, port, pub),
	})
	if err != nil {
		return nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, msg); err != nil {
		return nil, err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	_, cs0, cs1, err := hs.ReadMessage(nil, resp)
	if err != nil {
		return nil, err
	}
	if cs0 == nil || cs1 == nil {
		return nil, errors.New("noise handshake incomplete")
	}
	return newNoiseConn(conn, true, cs0, cs1), nil
}

// acceptE2E runs the Noise NK responder handshake for an agent stream and
// returns an encrypted connection.
func acceptE2E(conn net.Conn, priv ed25519.PrivateKey, name string, port int) (net.Conn, error) {
	xPriv, err := ed25519PrivateToX25519(priv)
	if err != nil {
		return nil, err
	}
	xPub, err := x25519Public(xPriv)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite(),
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: xPriv, Public: xPub},
		Prologue:      e2ePrologue(name, port, pub),
	})
	if err != nil {
		return nil, err
	}
	msg, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg); err != nil {
		return nil, err
	}
	resp, cs0, cs1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, resp); err != nil {
		return nil, err
	}
	if cs0 == nil || cs1 == nil {
		return nil, errors.New("noise handshake incomplete")
	}
	return newNoiseConn(conn, false, cs0, cs1), nil
}
