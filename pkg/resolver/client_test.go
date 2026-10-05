package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startMockDNSServer runs a local in-memory DNS server on a random port.
func startMockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	addr := pc.LocalAddr().String()
	cleanup := func() {
		_ = server.Shutdown()
	}

	return addr, cleanup
}

func TestClientExchangeUDP(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	}

	addr, cleanup := startMockDNSServer(t, handler)
	defer cleanup()

	client := NewClient(DefaultOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Exchange(ctx, addr, "example.com", dns.TypeA, nil)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp == nil || resp.Msg == nil {
		t.Fatalf("expected non-nil response")
	}

	if len(resp.Msg.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Msg.Answer))
	}

	aRecord, ok := resp.Msg.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != "93.184.216.34" {
		t.Fatalf("expected IP 93.184.216.34, got %v", resp.Msg.Answer[0])
	}

	if resp.RTT <= 0 {
		t.Errorf("expected RTT > 0, got %v", resp.RTT)
	}
}

func TestNormalizeServer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"8.8.8.8:5353", "8.8.8.8:5353"},
		{"[2001:4860:4860::8888]", "[2001:4860:4860::8888]:53"},
		{"https://cloudflare-dns.com/dns-query", "https://cloudflare-dns.com/dns-query"},
	}

	for _, tt := range tests {
		got := NormalizeServer(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeServer(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizeDoTServer(t *testing.T) {
	tests := []struct {
		input        string
		expectedAddr string
		expectedHost string
	}{
		{"1.1.1.1", "1.1.1.1:853", "1.1.1.1"},
		{"dns.google:853", "dns.google:853", "dns.google"},
		{"tls://1.1.1.1", "1.1.1.1:853", "1.1.1.1"},
	}

	for _, tt := range tests {
		addr, host := NormalizeDoTServer(tt.input)
		if addr != tt.expectedAddr || host != tt.expectedHost {
			t.Errorf("NormalizeDoTServer(%q) = (%q, %q), want (%q, %q)", tt.input, addr, host, tt.expectedAddr, tt.expectedHost)
		}
	}
}

func TestBuildQueryMessage(t *testing.T) {
	opts := QueryOptions{
		RecursionDesired: true,
		DNSSECOk:         true,
		EDNS0BufSize:     4096,
	}

	msg := BuildQueryMessage("example.com", dns.TypeA, opts)
	if !msg.RecursionDesired {
		t.Errorf("expected RecursionDesired=true")
	}

	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatalf("expected EDNS0 option present")
	}
	if opt.UDPSize() != 4096 {
		t.Errorf("expected UDP buffer size 4096, got %d", opt.UDPSize())
	}
	if !opt.Do() {
		t.Errorf("expected DNSSEC OK (DO) bit set")
	}
}

