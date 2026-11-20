package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
)

// Stream protocol v2. A v2 request starts with a 0x00 marker, which v1
// (host-length-prefixed) requests can never produce because host length 0 is
// invalid. This lets new nodes keep serving legacy v1 clearnet clients.
const (
	streamV2Marker    byte = 0
	streamVersion2    byte = 2
	streamTypeConnect byte = 2
)

const (
	respOK              byte = 0
	respNotFound        byte = 1
	respE2EUnavailable  byte = 2
	respBadRequest      byte = 3
	respExitUnavailable byte = 4
)

const e2eVersion1 byte = 1

// writeRequestHeaderV2 writes a v2 connect request.
func writeRequestHeaderV2(w io.Writer, host string, port int) error {
	host = NormalizeHost(host)
	if len(host) == 0 || len(host) > 255 {
		return errors.New("invalid host length")
	}
	buf := make([]byte, 0, 4+len(host)+2)
	buf = append(buf, streamV2Marker, streamVersion2, streamTypeConnect, byte(len(host)))
	buf = append(buf, host...)
	buf = append(buf, byte(port>>8), byte(port))
	_, err := w.Write(buf)
	return err
}

// readRequest reads either a v1 or v2 request and reports whether it was v2.
func readRequest(r io.Reader) (string, int, bool, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return "", 0, false, err
	}
	if first[0] != streamV2Marker {
		host, port, err := readHostPortWithLen(r, int(first[0]))
		return host, port, false, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 0, true, err
	}
	if hdr[0] != streamVersion2 {
		return "", 0, true, errors.New("unsupported stream version")
	}
	if hdr[1] != streamTypeConnect {
		return "", 0, true, errors.New("unsupported request type")
	}
	host, port, err := readHostPort(r)
	return host, port, true, err
}

// readHostPort reads a host-length-prefixed host and a 16-bit port.
func readHostPort(r io.Reader) (string, int, error) {
	var lenBuf [1]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", 0, err
	}
	return readHostPortWithLen(r, int(lenBuf[0]))
}

func readHostPortWithLen(r io.Reader, n int) (string, int, error) {
	if n == 0 {
		return "", 0, errors.New("invalid host length")
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", 0, err
	}
	host := string(buf[:n])
	port := int(binary.BigEndian.Uint16(buf[n:]))
	return host, port, nil
}

// writeResponseHeader writes the node's response to a v2 request.
func writeResponseHeader(w io.Writer, status byte, e2e bool, pub ed25519.PublicKey, version byte) error {
	buf := []byte{status}
	if status == respOK {
		var flags byte
		if e2e {
			flags |= 1
		}
		buf = append(buf, flags)
		if e2e {
			if len(pub) != ed25519.PublicKeySize {
				return errors.New("invalid agent public key")
			}
			buf = append(buf, pub...)
			buf = append(buf, version)
		}
	}
	_, err := w.Write(buf)
	return err
}

// readResponseHeader parses the node's response to a v2 request.
func readResponseHeader(r io.Reader) (byte, bool, ed25519.PublicKey, byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, false, nil, 0, err
	}
	status := b[0]
	if status != respOK {
		return status, false, nil, 0, nil
	}
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, false, nil, 0, err
	}
	e2e := b[0]&1 != 0
	if !e2e {
		return status, false, nil, 0, nil
	}
	pub := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(r, pub); err != nil {
		return 0, false, nil, 0, err
	}
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, false, nil, 0, err
	}
	return status, true, ed25519.PublicKey(pub), b[0], nil
}
