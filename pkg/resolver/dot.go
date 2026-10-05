package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DoTClient performs DNS queries over TLS (RFC 7858, port 853).
type DoTClient struct {
	client  *dns.Client
	timeout time.Duration
}

// NewDoTClient creates a DoT client with modern TLS configuration.
func NewDoTClient(timeout time.Duration) *DoTClient {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	return &DoTClient{
		timeout: timeout,
		client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeout,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// NormalizeDoTServer formats the server address for port 853.
func NormalizeDoTServer(server string) (string, string) {
	server = strings.TrimSpace(server)
	server = strings.TrimPrefix(server, "tls://")

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		port = "853"
	}
	return net.JoinHostPort(host, port), host
}

// Exchange sends a DNS query over TLS.
func (c *DoTClient) Exchange(ctx context.Context, server string, qname string, qtype uint16, opts QueryOptions) (*Response, error) {
	msg := BuildQueryMessage(qname, qtype, opts)
	return c.ExchangeMsg(ctx, server, msg)
}

// ExchangeMsg sends a prebuilt dns.Msg over TLS.
func (c *DoTClient) ExchangeMsg(ctx context.Context, server string, msg *dns.Msg) (*Response, error) {
	target, serverName := NormalizeDoTServer(server)

	// Configure TLS server name for SNI verification
	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: c.timeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		},
	}

	type result struct {
		resp *dns.Msg
		rtt  time.Duration
		err  error
	}

	ch := make(chan result, 1)

	go func() {
		start := time.Now()
		r, rtt, err := client.Exchange(msg, target)
		if err != nil {
			ch <- result{resp: nil, rtt: time.Since(start), err: err}
			return
		}
		ch <- result{resp: r, rtt: rtt, err: nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("dot exchange with %s failed: %w", target, res.err)
		}
		return &Response{
			Msg:       res.resp,
			RTT:       res.rtt,
			Server:    target,
			Protocol:  "dot",
			Truncated: res.resp != nil && res.resp.Truncated,
		}, nil
	}
}
