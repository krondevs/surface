package main

import (
	"bufio"
	"context"
	"log"
	"net"
)

type TargetDialer interface {
	DialTarget(host string, port int) (net.Conn, error)
}

type connReader struct {
	net.Conn
	r *bufio.Reader
}

func (c *connReader) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

type ProxyServer struct {
	listen string
	dialer TargetDialer
	logger *log.Logger
}

func NewProxyServer(listen string, dialer TargetDialer, logger *log.Logger) *ProxyServer {
	return &ProxyServer{listen: listen, dialer: dialer, logger: logger}
}

func (p *ProxyServer) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	p.logger.Printf("proxy listening on %s", p.listen)
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go p.handle(conn)
	}
}

func (p *ProxyServer) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		p.handleSOCKS5(conn, reader)
		return
	}
	p.handleHTTP(conn, reader)
}
