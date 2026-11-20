package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"time"
)

var errOnionProxyRequired = errors.New("onion destination requires onion_proxy (Tor SOCKS5)")

type InternetDialer struct {
	resolver   *net.Resolver
	dialer     *net.Dialer
	proxy      proxyDialer
	onionProxy proxyDialer
	fallback   bool
	logger     *log.Logger
}

func NewInternetDialer(dnsServers []string, exitProxy, onionProxy string, fallback bool, logger *log.Logger) (*InternetDialer, error) {
	proxy, err := parseExitProxy(exitProxy)
	if err != nil {
		return nil, err
	}
	onion, err := parseOnionProxy(onionProxy)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	d := &InternetDialer{
		dialer:     dialer,
		proxy:      proxy,
		onionProxy: onion,
		fallback:   fallback,
		logger:     logger,
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

func (d *InternetDialer) OnionDescription() string {
	if d.onionProxy == nil {
		return "disabled"
	}
	return d.onionProxy.String()
}

func (d *InternetDialer) DialTarget(host string, port int) (net.Conn, error) {
	host = NormalizeHost(host)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// .onion destinations must go through Tor and never fall back to a direct
	// connection: a direct dial would leak the onion name to the DNS resolver.
	if IsOnionName(host) {
		if d.onionProxy == nil {
			return nil, errOnionProxyRequired
		}
		conn, err := d.onionProxy.DialTarget(ctx, host, port)
		if err != nil && d.logger != nil {
			d.logger.Printf("onion exit %s failed for %s: %v", d.onionProxy.String(), host, err)
		}
		return conn, err
	}

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
