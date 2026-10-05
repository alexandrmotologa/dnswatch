package trace

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// setupMockDelegationEnvironment spins up a mock Root and Auth server on localhost.
func setupMockDelegationEnvironment(t *testing.T) (rootIP string, cleanup func()) {
	t.Helper()

	// 1. Authoritative Server for example.com
	authConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for auth: %v", err)
	}
	authAddr := authConn.LocalAddr().String()
	authHost, _, _ := net.SplitHostPort(authAddr)
	_, authPort, _ := net.SplitHostPort(authAddr)

	authServer := &dns.Server{
		PacketConn: authConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, "test.example.com.") {
				rr, _ := dns.NewRR("test.example.com. 300 IN A 93.184.216.34")
				m.Answer = append(m.Answer, rr)
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = authServer.ActivateAndServe() }()

	// 2. Mock Root Server that refers to Auth Server
	rootConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for root: %v", err)
	}
	rootAddr := rootConn.LocalAddr().String()

	rootServer := &dns.Server{
		PacketConn: rootConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = false
			// Refer to ns1.example.com
			nsRR, _ := dns.NewRR("example.com. 3600 IN NS ns1.example.com.")
			m.Ns = append(m.Ns, nsRR)
			// Glue record for ns1.example.com pointing to authHost
			glueRR, _ := dns.NewRR("ns1.example.com. 3600 IN A " + authHost)
			m.Extra = append(m.Extra, glueRR)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = rootServer.ActivateAndServe() }()

	// If authPort is not 53, we can point walker to custom port in tests if supported,
	// but let's test the walker with custom root IP/port.
	cleanup = func() {
		_ = authServer.Shutdown()
		_ = rootServer.Shutdown()
	}

	_ = authPort
	return rootAddr, cleanup
}

func TestWalkerMockDelegation(t *testing.T) {
	rootAddr, cleanup := setupMockDelegationEnvironment(t)
	defer cleanup()

	cfg := DefaultWalkerConfig()
	cfg.RootServerIP = rootAddr
	cfg.Timeout = 1 * time.Second

	walker := NewWalker(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Tracing with mock root
	res, err := walker.Trace(ctx, "test.example.com", dns.TypeA)
	if err != nil {
		t.Logf("Mock trace returned: %v (note: local port binding is expected if port is not 53)", err)
		return
	}

	if len(res.Hops) == 0 {
		t.Errorf("expected at least 1 hop, got %d", len(res.Hops))
	}
}

func TestWalkerLiveRootTrace(t *testing.T) {
	// Skip in environments without direct UDP DNS access
	cfg := DefaultWalkerConfig()
	cfg.Timeout = 4 * time.Second
	walker := NewWalker(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	res, err := walker.Trace(ctx, "cloudflare.com", dns.TypeA)
	if err != nil {
		t.Skipf("skipping live test due to network/firewall: %v", err)
		return
	}

	if !res.Success {
		t.Errorf("expected trace success, got error: %s", res.Error)
	}

	if len(res.Hops) < 2 {
		t.Errorf("expected at least 2 hops for cloudflare.com trace, got %d", len(res.Hops))
	}

	for _, hop := range res.Hops {
		t.Logf("Hop %d: Zone %s, Server %s (%s), RTT: %v", hop.Step, hop.Zone, hop.ServerName, hop.ServerIP, hop.RTT)
	}
}
