package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type proxyDialer interface {
	DialTarget(ctx context.Context, host string, port int) (net.Conn, error)
	String() string
}

func parseExitProxy(raw string) (proxyDialer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid exit_proxy: %w", err)
	}
	if u.Host == "" {
		return nil, errors.New("exit_proxy: missing host")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("exit_proxy: address must be host:port (%q)", u.Host)
	}
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return &socks5Dialer{addr: u.Host, user: user, pass: pass}, nil
	case "http":
		return &httpConnectDialer{addr: u.Host, user: user, pass: pass}, nil
	default:
		return nil, fmt.Errorf("exit_proxy: unsupported scheme %q (use socks5 or http)", u.Scheme)
	}
}

type socks5Dialer struct {
	addr string
	user string
	pass string
}

func (d *socks5Dialer) String() string {
	return "socks5://" + d.addr
}

func (d *socks5Dialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := d.handshake(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *socks5Dialer) handshake(conn net.Conn, host string, port int) error {
	methods := []byte{0x00}
	if d.user != "" {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return errors.New("socks5: bad proxy version")
	}
	switch response[1] {
	case 0x00:
	case 0x02:
		if err := d.authenticate(conn); err != nil {
			return err
		}
	case 0xFF:
		return errors.New("socks5: proxy rejected authentication methods")
	default:
		return errors.New("socks5: unsupported authentication method")
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 0x01)
			request = append(request, v4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: host too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	request = append(request, portBuf[:]...)
	if _, err := conn.Write(request); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed (code %d)", head[1])
	}
	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		addrLen = int(length[0])
	default:
		return errors.New("socks5: bad address type in reply")
	}
	discard := make([]byte, addrLen+2)
	_, err := io.ReadFull(conn, discard)
	return err
}

func (d *socks5Dialer) authenticate(conn net.Conn) error {
	if len(d.user) > 255 || len(d.pass) > 255 {
		return errors.New("socks5: credentials too long")
	}
	msg := []byte{0x01, byte(len(d.user))}
	msg = append(msg, d.user...)
	msg = append(msg, byte(len(d.pass)))
	msg = append(msg, d.pass...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

type httpConnectDialer struct {
	addr string
	user string
	pass string
}

func (d *httpConnectDialer) String() string {
	return "http://" + d.addr
}

func (d *httpConnectDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if d.user != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(d.user + ":" + d.pass))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", credentials)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("http proxy: CONNECT failed with status %d", response.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	if reader.Buffered() > 0 {
		return &connReader{Conn: conn, r: reader}, nil
	}
	return conn, nil
}
