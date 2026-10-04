package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

type InternetDialer struct {
	resolver *net.Resolver
	dialer   *net.Dialer
}

func NewInternetDialer(dnsServers []string) *InternetDialer {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	resolver := net.DefaultResolver
	if len(dnsServers) > 0 {
		servers := append([]string{}, dnsServers...)
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var lastErr error
				for _, server := range servers {
					conn, err := dialer.DialContext(ctx, "udp", server)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				if lastErr == nil {
					lastErr = errors.New("no dns servers available")
				}
				return nil, lastErr
			},
		}
	}
	return &InternetDialer{resolver: resolver, dialer: dialer}
}

func (d *InternetDialer) DialTarget(host string, port int) (net.Conn, error) {
	if ip := net.ParseIP(host); ip != nil {
		return d.dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.dialer.Dial("tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses resolved")
	}
	return nil, lastErr
}
