// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// statusTestStatus is a minimal ipnstate.Status used by serve-status tests.
var statusTestStatus = &ipnstate.Status{
	BackendState: ipn.Running.String(),
	Self: &ipnstate.PeerStatus{
		DNSName: "foo.test.ts.net.",
	},
	CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "test.ts.net"},
}

func TestPrintServeStatusTrees(t *testing.T) {
	tests := []struct {
		name    string
		sc      *ipn.ServeConfig
		wantSub []string // substrings that must appear in the output
		notWant []string // substrings that must NOT appear
	}{
		{
			name: "node_web_tailnet_only",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
			},
			wantSub: []string{
				"https://foo.test.ts.net",
				"tailnet only",
				"proxy",
				"http://127.0.0.1:3000",
			},
			notWant: []string{"Service ", "Funnel on"},
		},
		{
			name: "node_tcp_funnel_on",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{2222: {TCPForward: "127.0.0.1:22"}},
				AllowFunnel: map[ipn.HostPort]bool{
					"foo.test.ts.net:2222": true,
				},
			},
			wantSub: []string{
				"tcp://foo.test.ts.net:2222",
				"TLS over TCP",
				"Funnel on",
				"|--> tcp://127.0.0.1:22",
			},
			notWant: []string{"Service ", "tailnet only"},
		},
		{
			name: "service_web_only",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:db": {
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"db.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://127.0.0.1:5432"},
							}},
						},
					},
				},
			},
			wantSub: []string{
				"svc:db https://db.test.ts.net",
				"proxy",
				"http://127.0.0.1:5432",
			},
			notWant: []string{"Funnel on", "Service svc:"},
		},
		{
			name: "service_tcp_forward",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:ssh": {
						TCP: map[uint16]*ipn.TCPPortHandler{2222: {TCPForward: "127.0.0.1:22"}},
					},
				},
			},
			wantSub: []string{
				"svc:ssh tcp://ssh.test.ts.net:2222",
				"|--> tcp://127.0.0.1:22",
			},
			notWant: []string{"Service svc:"},
		},
		{
			name: "service_tun",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:vpn": {Tun: true},
				},
			},
			wantSub: []string{
				"svc:vpn tun (L3 forwarding)",
			},
			notWant: []string{"https://", "tcp://", "Funnel on", "Service svc:"},
		},
		{
			name: "node_and_services_mixed",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
				AllowFunnel: map[ipn.HostPort]bool{
					"foo.test.ts.net:443": true,
				},
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:db": {
						TCP: map[uint16]*ipn.TCPPortHandler{5432: {TCPForward: "127.0.0.1:5432"}},
					},
				},
			},
			wantSub: []string{
				"https://foo.test.ts.net",
				"Funnel on",
				"svc:db tcp://db.test.ts.net:5432",
				"|--> tcp://127.0.0.1:5432",
			},
			notWant: []string{"Service svc:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tstest.Replace(t, &Stdout, io.Writer(&buf))
			tstest.Replace(t, &Stderr, io.Discard)

			if err := printServeStatusTrees(tt.sc, statusTestStatus); err != nil {
				t.Fatalf("printServeStatusTrees: %v", err)
			}
			out := buf.String()
			for _, s := range tt.wantSub {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q\n--- output ---\n%s", s, out)
				}
			}
			for _, s := range tt.notWant {
				if strings.Contains(out, s) {
					t.Errorf("output unexpectedly contains %q\n--- output ---\n%s", s, out)
				}
			}
		})
	}
}

// TestPrintServeStatusTreesParity asserts that every service name and
// HostPort key visible in the JSON serialization of a ServeConfig also
// appears in the human-readable output. This is the parity contract from
// issue #34163.
func TestPrintServeStatusTreesParity(t *testing.T) {
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443:  {HTTPS: true},
			2222: {TCPForward: "127.0.0.1:22"},
		},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: "http://127.0.0.1:3000"},
			}},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			"foo.test.ts.net:2222": true,
		},
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:db": {
				TCP: map[uint16]*ipn.TCPPortHandler{5432: {TCPForward: "127.0.0.1:5432"}},
			},
			"svc:web": {
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"web.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/api": {Proxy: "http://127.0.0.1:9000"},
					}},
				},
			},
			"svc:vpn": {Tun: true},
		},
	}

	// JSON dump; just verify it's non-empty so we don't assert on
	// schema-internal field names.
	if _, err := json.MarshalIndent(sc, "", "  "); err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	var buf bytes.Buffer
	tstest.Replace(t, &Stdout, io.Writer(&buf))
	tstest.Replace(t, &Stderr, io.Discard)

	if err := printServeStatusTrees(sc, statusTestStatus); err != nil {
		t.Fatalf("printServeStatusTrees: %v", err)
	}
	out := buf.String()

	// Every service name in sc.Services must appear in the human output.
	for name := range sc.Services {
		if !strings.Contains(out, name.String()) {
			t.Errorf("human output missing service %q\n%s", name, out)
		}
	}
	// Every node-level Web HostPort must appear (host portion at least).
	for hp := range sc.Web {
		host := strings.SplitN(string(hp), ":", 2)[0]
		if !strings.Contains(out, host) {
			t.Errorf("human output missing node web host %q\n%s", host, out)
		}
	}
}
