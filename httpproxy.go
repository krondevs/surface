package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

func (p *ProxyServer) handleHTTP(client net.Conn, reader *bufio.Reader) {
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if request.Method == http.MethodConnect {
		host, port := splitHostPort(request.Host, 443)
		upstream, err := p.dialer.DialTarget(host, port)
		if err != nil {
			writeHTTPStatus(client, http.StatusBadGateway, "Bad Gateway")
			return
		}
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			upstream.Close()
			return
		}
		pipe(&connReader{Conn: client, r: reader}, upstream)
		return
	}

	host := request.URL.Host
	if host == "" {
		host = request.Host
	}
	targetHost, port := splitHostPort(host, 80)
	upstream, err := p.dialer.DialTarget(targetHost, port)
	if err != nil {
		writeHTTPStatus(client, http.StatusBadGateway, "Bad Gateway")
		return
	}
	defer upstream.Close()

	request.Header.Del("Proxy-Connection")
	request.Header.Del("Proxy-Authorization")
	request.RequestURI = ""
	request.URL.Scheme = ""
	request.URL.Host = ""
	if err := request.Write(upstream); err != nil {
		return
	}
	io.Copy(client, upstream)
}

func splitHostPort(host string, defaultPort int) (string, int) {
	host = NormalizeHost(host)
	if host == "" {
		return host, defaultPort
	}
	h, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return host, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		port = defaultPort
	}
	return h, port
}

func writeHTTPStatus(conn net.Conn, code int, message string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, message)
}
