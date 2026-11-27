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
		pipeMetered(&connReader{Conn: client, r: reader}, upstream, p.meter, trafficClassForHost(host))
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
	class := trafficClassForHost(targetHost)
	bodyWriter := &countingWriter{w: upstream, meter: p.meter, class: class}
	if err := request.Write(bodyWriter); err != nil {
		return
	}
	n, _ := io.Copy(client, upstream)
	p.meter.Add(class, false, n)
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
