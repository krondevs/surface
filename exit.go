package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"time"
)

type InternetDialer struct {
	resolver *net.Resolver
	dialer   *net.Dialer
	proxy    proxyDialer
	fallback bool
	logger   *log.Logger
}

func NewInternetDialer(dnsServers []string, exitProxy string, fallback bool, logger *log.Logger) (*InternetDialer, error) {
	proxy, err := parseExitProxy(exitProxy)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	d := &InternetDialer{
		dialer:   dialer,
		proxy:    proxy,
		fallback: fallback,
		logger:   logger,
	}
	if proxy == nil {
		d.resolver = buildResolver(dnsServers, dialer)
	}
	return d, nil
}

func buildResolver(dnsServers []string, dialer *net.Dialer) *net.Resolver {
	if len(dnsServers) == 0 {
		return net.DefaultResolver
	}
	servers := append([]string{}, dnsServers...)
	return &net.Resolver{
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

func (d *InternetDialer) ExitDescription() string {
	if d.proxy == nil {
		return "direct"
	}
	return d.proxy.String()
}

func (d *InternetDialer) DialTarget(host string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if d.proxy != nil {
		conn, err := d.proxy.DialTarget(ctx, host, port)
		if err == nil {
			return conn, nil
		}
		if !d.fallback {
			return nil, err
		}
		if d.logger != nil {
			d.logger.Printf("exit proxy %s failed (%v); falling back to direct", d.proxy.String(), err)
		}
	}
	return d.directDial(ctx, host, port)
}

func (d *InternetDialer) directDial(ctx context.Context, host string, port int) (net.Conn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	if ip := net.ParseIP(host); ip != nil {
		return d.dialer.DialContext(ctx, "tcp", address)
	}
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(port)))
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
