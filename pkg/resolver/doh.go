package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHClient performs DNS queries over HTTPS (RFC 8484).
type DoHClient struct {
	httpClient *http.Client
}

// NewDoHClient creates an optimized HTTP/2 client for DoH queries.
func NewDoHClient(timeout time.Duration) *DoHClient {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &DoHClient{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

// Exchange sends an RFC 8484 DNS POST query to a DoH endpoint.
func (c *DoHClient) Exchange(ctx context.Context, endpointURL string, qname string, qtype uint16, opts QueryOptions) (*Response, error) {
	msg := BuildQueryMessage(qname, qtype, opts)
	return c.ExchangeMsg(ctx, endpointURL, msg)
}

// ExchangeMsg sends a prebuilt dns.Msg over DoH.
func (c *DoHClient) ExchangeMsg(ctx context.Context, endpointURL string, msg *dns.Msg) (*Response, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create doh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "DNSWatch/1.0")

	start := time.Now()
	httpResp, err := c.httpClient.Do(req)
	rtt := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("doh request to %s failed: %w", endpointURL, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server %s returned status %d", endpointURL, httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read doh response body: %w", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack doh dns response: %w", err)
	}

	return &Response{
		Msg:       respMsg,
		RTT:       rtt,
		Server:    endpointURL,
		Protocol:  "doh",
		Truncated: respMsg.Truncated,
	}, nil
}
