// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/slicesx"
)

// isServeConfigEmpty reports whether sc has no user-visible configuration
// to render in the non-JSON status output.
func isServeConfigEmpty(sc *ipn.ServeConfig) bool {
	return sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.Services) == 0 && len(sc.AllowFunnel) == 0)
}

// printServeStatusTrees prints the tree-style human-readable status of sc,
// including any node-level TCP and Web serve entries and any configured
// services, to the package Stdout. It does not print the funnel-status
// header, the no-config message, or the trailing funnel warning — callers
// are expected to handle those.
//
// Ordering is deterministic: node TCP forwards (existing behavior), then
// node Web entries by HostPort, then services by name.
func printServeStatusTrees(sc *ipn.ServeConfig, st *ipnstate.Status) error {
	if sc == nil {
		return nil
	}
	if sc.IsTCPForwardingAny() {
		if err := printTCPStatusTree(context.Background(), sc, st); err != nil {
			return err
		}
		printf("\n")
	}
	for _, hp := range slices.Sorted(maps.Keys(sc.Web)) {
		if err := printWebStatusTree(sc, hp); err != nil {
			return err
		}
		printf("\n")
	}
	for _, name := range slices.Sorted(maps.Keys(sc.Services)) {
		if err := printServiceStatusTree(sc, st, name); err != nil {
			return err
		}
	}
	return nil
}

// printServiceStatusTree prints the tree-style status for a single
// configured service. Each rendered URL/forward line is prefixed with the
// service name and a space (e.g. "svc:db https://db.example.ts.net") so
// service entries are visually distinct from node-level serves.
func printServiceStatusTree(sc *ipn.ServeConfig, st *ipnstate.Status, name tailcfg.ServiceName) error {
	svc, ok := sc.Services[name]
	if !ok || svc == nil {
		return nil
	}

	if svc.Tun {
		printf("%s tun (L3 forwarding)\n\n", name)
		return nil
	}

	suffix := ""
	if st != nil && st.CurrentTailnet != nil {
		suffix = st.CurrentTailnet.MagicDNSSuffix
	}
	host := name.WithoutPrefix()
	if suffix != "" {
		host = host + "." + suffix
	}

	// TCP forwards configured directly on the service.
	tcpPorts := slices.Sorted(maps.Keys(svc.TCP))
	for _, p := range tcpPorts {
		h := svc.TCP[p]
		if h == nil || h.TCPForward == "" {
			continue
		}
		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}
		hp := ipn.HostPort(net.JoinHostPort(host, strconv.Itoa(int(p))))
		printf("%s tcp://%s (%s)\n", name, hp, tlsStatus)
		printf("|--> tcp://%s\n\n", h.TCPForward)
	}

	// Web entries (HTTP/HTTPS).
	for _, hp := range slices.Sorted(maps.Keys(svc.Web)) {
		if err := printServiceWebStatusTree(sc, svc, name, hp); err != nil {
			return err
		}
		printf("\n")
	}

	return nil
}

// printServiceWebStatusTree renders one entry of svc.Web for the given
// service. It mirrors the layout of printWebStatusTree but uses
// service-specific scheme/handler lookups via sc.IsServingHTTP(_, name).
func printServiceWebStatusTree(sc *ipn.ServeConfig, svc *ipn.ServiceConfig, name tailcfg.ServiceName, hp ipn.HostPort) error {
	host, portStr, _ := net.SplitHostPort(string(hp))
	port, err := parseServePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	scheme := "https"
	if sc.IsServingHTTP(port, name) {
		scheme = "http"
	}
	portPart := ":" + portStr
	if scheme == "http" && portStr == "80" || scheme == "https" && portStr == "443" {
		portPart = ""
	}
	printf("%s %s://%s%s\n", name, scheme, host, portPart)

	web := svc.Web[hp]
	if web == nil || len(web.Handlers) == 0 {
		return nil
	}
	mounts := slicesx.MapKeys(web.Handlers)
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) < len(mounts[j])
	})
	maxLen := len(mounts[len(mounts)-1])
	for _, m := range mounts {
		h := web.Handlers[m]
		t, d := serveHandlerDesc(h)
		printf("|-- %s%s %-5s %s\n", m, strings.Repeat(" ", maxLen-len(m)), t, d)
	}
	return nil
}

// serveHandlerDesc returns the type label and description for an HTTPHandler,
// matching the format used by the existing node Web tree printer.
func serveHandlerDesc(h *ipn.HTTPHandler) (string, string) {
	switch {
	case h.Path != "":
		return "path", h.Path
	case h.Proxy != "":
		return "proxy", h.Proxy
	case h.Text != "":
		return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
	}
	return "", ""
}
