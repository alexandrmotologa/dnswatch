package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Client executes DNS exchanges over standard UDP/TCP transport.
type Client struct {
	defaultOpts QueryOptions
	udpClient   *dns.Client
	tcpClient   *dns.Client
}

// NewClient creates a configured DNS client.
func NewClient(opts QueryOptions) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		defaultOpts: opts,
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout * 2,
		},
	}
}

// NormalizeServer formats an IP or hostname with port 53.
func NormalizeServer(server string) string {
	server = strings.TrimSpace(server)
	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "http://") {
		return server
	}

	// Check if already contains port
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}

	// Handle bracketed IPv6 like [2001:db8::1]
	if strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]") {
		return server + ":53"
	}

	// Handle unbracketed IPv6
	if strings.Contains(server, ":") {
		return fmt.Sprintf("[%s]:53", server)
	}

	return net.JoinHostPort(server, "53")
}

// BuildQueryMessage creates a standard DNS query message.
func BuildQueryMessage(qname string, qtype uint16, opts QueryOptions) *dns.Msg {
	msg := new(dns.Msg)
	qname = dns.Fqdn(qname)
	msg.SetQuestion(qname, qtype)
	msg.RecursionDesired = opts.RecursionDesired

	if opts.EDNS0BufSize > 0 || opts.DNSSECOk {
		bufSize := opts.EDNS0BufSize
		if bufSize == 0 {
			bufSize = 1232
		}
		msg.SetEdns0(bufSize, opts.DNSSECOk)
	}

	return msg
}

// Exchange executes a DNS query against a target nameserver.
// If the UDP response is truncated (TC flag set), it automatically retries via TCP.
func (c *Client) Exchange(ctx context.Context, server string, qname string, qtype uint16, customOpts *QueryOptions) (*Response, error) {
	opts := c.defaultOpts
	if customOpts != nil {
		opts = *customOpts
	}

	target := NormalizeServer(server)
	msg := BuildQueryMessage(qname, qtype, opts)

	// Channel for receiving async exchange result
	type result struct {
		resp *dns.Msg
		rtt  time.Duration
		err  error
		net  string
	}

	ch := make(chan result, 1)

	go func() {
		start := time.Now()
		r, rtt, err := c.udpClient.Exchange(msg, target)
		if err == nil && r != nil && r.Truncated {
			// Fallback to TCP upon truncation
			rTcp, _, tcpErr := c.tcpClient.Exchange(msg, target)
			if tcpErr == nil && rTcp != nil {
				ch <- result{resp: rTcp, rtt: time.Since(start), err: nil, net: "tcp"}
				return
			}
			// If TCP fails, return original truncated UDP response
			ch <- result{resp: r, rtt: rtt, err: nil, net: "udp"}
			return
		}
		ch <- result{resp: r, rtt: rtt, err: err, net: "udp"}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("exchange with %s failed: %w", target, res.err)
		}
		return &Response{
			Msg:       res.resp,
			RTT:       res.rtt,
			Server:    target,
			Protocol:  res.net,
			Truncated: res.resp != nil && res.resp.Truncated,
		}, nil
	}
}

// ExchangeMsg executes a prepared dns.Msg.
func (c *Client) ExchangeMsg(ctx context.Context, server string, msg *dns.Msg) (*Response, error) {
	target := NormalizeServer(server)
	type result struct {
		resp *dns.Msg
		rtt  time.Duration
		err  error
		net  string
	}

	ch := make(chan result, 1)

	go func() {
		start := time.Now()
		r, rtt, err := c.udpClient.Exchange(msg, target)
		if err == nil && r != nil && r.Truncated {
			rTcp, tcpRtt, tcpErr := c.tcpClient.Exchange(msg, target)
			if tcpErr == nil && rTcp != nil {
				ch <- result{resp: rTcp, rtt: rtt + tcpRtt, err: nil, net: "tcp"}
				return
			}
			ch <- result{resp: r, rtt: time.Since(start), err: nil, net: "udp"}
			return
		}
		ch <- result{resp: r, rtt: rtt, err: err, net: "udp"}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("exchange with %s failed: %w", target, res.err)
		}
		return &Response{
			Msg:       res.resp,
			RTT:       res.rtt,
			Server:    target,
			Protocol:  res.net,
			Truncated: res.resp != nil && res.resp.Truncated,
		}, nil
	}
}
