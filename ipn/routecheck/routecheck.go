// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck performs status checks for routes from the current host.
package routecheck

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

var (
	metricNeedsRefresh = clientmetric.NewCounter("routecheck_needs_refresh")
	metricRefresh      = clientmetric.NewCounter("routecheck_refresh")
)

// DebugClientSideReachabilityRoutecheck reports whether routecheck should be forced on or off.
// If the TS_DEBUG_CLIENT_SIDE_REACHABILITY_ROUTECHECK environment variable is true,
// then routecheck is forced on. If it is false, then routecheck is forced off.
// If unset, then the client respects the client-side-reachability:routecheck node attributes.
var DebugClientSideReachabilityRoutecheck = envknob.RegisterOptBool("TS_DEBUG_CLIENT_SIDE_REACHABILITY_ROUTECHECK")

// IsEnabled reports whether routecheck probing has been enabled for this client.
func IsEnabled(self tailcfg.NodeView) bool {
	if v, ok := DebugClientSideReachabilityRoutecheck().Get(); ok {
		return v // forced
	}
	if !self.Valid() {
		return false
	}
	return self.HasCap(tailcfg.NodeAttrClientSideReachability) &&
		self.HasCap(tailcfg.NodeAttrClientSideReachabilityRouteCheck)
}

// Client generates Reports describing the result of both passive and active
// reachability probing.
type Client struct {
	// Verbose enables verbose logging.
	Verbose bool

	// Logf optionally specifies where to log to.
	// If nil, log.Printf is used.
	Logf logger.Logf

	// These elements are read-only after initialization.
	nb     NodeBackender
	nm     NetMapper
	pinger Pinger

	// NeedsRefresh is a flag that indicates that a new report is needed.
	needsRefresh chan struct{}
	stop         context.CancelFunc
	report       atomic.Pointer[Report]

	// NetMapAvailable is raised when the first network map is received
	// after connecting to the control plane.
	netMapAvailable sync.Cond
}

// NetMapper is the interface that returns the current [netmap.NetworkMap].
type NetMapper interface {
	// NetMap returns the latest cached network map received from controlclient,
	// or nil if no network map was received yet.
	NetMap() *netmap.NetworkMap
}

// NodeBackender is the interface that returns the current [NodeBackend].
type NodeBackender interface {
	NodeBackend() NodeBackend
}

// NodeBackend is an interface to query the current node and its peers.
//
// It is not a snapshot in time but is locked to a particular node.
type NodeBackend interface {
	// Self returns the current node.
	Self() tailcfg.NodeView

	// Peers returns all the current peers.
	Peers() []tailcfg.NodeView
}

// Pinger is the interface that wraps the [tailscale.com/ipn/ipnlocal.LocalBackend.Ping] method.
type Pinger interface {
	Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult))
}

// NewClient returns a client that probes its peers using this LocalBackend.
func NewClient(logf logger.Logf, nb NodeBackender, nm NetMapper, pinger Pinger) (*Client, error) {
	if nb == nil {
		return nil, errors.New("NodeBackender must be set")
	}
	if nm == nil {
		return nil, errors.New("NetMapper must be set")
	}
	if pinger == nil {
		return nil, errors.New("Pinger must be set")
	}
	c := &Client{
		Logf:   logf,
		nb:     nb,
		nm:     nm,
		pinger: pinger,

		needsRefresh: make(chan struct{}, 1),
	}
	c.netMapAvailable.L = new(sync.Mutex)
	return c, nil
}

func (c *Client) NetMapAvailable(nm *netmap.NetworkMap) {
	if nm == nil {
		return // client disconnected
	}
	c.netMapAvailable.Broadcast()
}

func (c *Client) waitForNetMap(ctx context.Context) (*netmap.NetworkMap, error) {
	cond := &c.netMapAvailable

	stopf := context.AfterFunc(ctx, func() {
		// Lock cond to ensure that Broadcast is called after the Wait below.
		cond.L.Lock()
		defer cond.L.Unlock()
		cond.Broadcast()
	})
	defer stopf()

	cond.L.Lock()
	defer cond.L.Unlock()
	for {
		nm := c.nm.NetMap()
		if nm != nil {
			return nm, nil
		}
		cond.Wait()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

// Refresh generates a new reachability report and returns it.
// A peer is considered unreachable if it doesn’t respond within the timeout.
func (c *Client) Refresh(ctx context.Context, timeout time.Duration) (*Report, error) {
	metricRefresh.Add(1)
	r, err := c.ProbeAllHARouters(ctx, 5, timeout)
	if err != nil {
		return nil, fmt.Errorf("error probing routers: %w", err)
	}
	return r, nil
}

// NeedsRefresh signals the need for a [Client.Refresh] to probe for a new report,
// which will be done in the background by [Client.Start].
func (c *Client) NeedsRefresh() {
	select {
	case c.needsRefresh <- struct{}{}:
		metricNeedsRefresh.Add(1)
	default:
		// needsRefresh has already been raised, so debounce.
	}
}

// Start runs periodic probes that compile routecheck reports.
// Use [Client.Close] to stop probing.
func (c *Client) Start(ctx context.Context) {
	first := true
	ctx, cancel := context.WithCancel(ctx)
	c.stop = cancel
	for {
		select {
		case <-c.needsRefresh:
			nm := c.nm.NetMap()
			if nm == nil {
				continue // The report wasn’t available.
			}

			if first {
				r := c.bootstrap(nm)
				c.report.Store(r)
				first = false
			}

			// TODO(sfllaw): Examine the shape of the overlapping
			// routers and only probe if the routing table has
			// changed sufficiently. For instance, a new router has
			// come online or a router has been removed or a set of
			// routers no longer overlap.

			r, err := c.Refresh(ctx, DefaultTimeout)
			if err != nil {
				c.logf("%v", err)
				continue
			}
			c.report.Store(r)
		case <-ctx.Done():
			return
		}
	}
}

// Bootstrap assumes that nodes that are connected to the control plane are reachable,
// while waiting for the first probe to finish.
func (c *Client) bootstrap(nm *netmap.NetworkMap) *Report {
	if nm == nil {
		return nil
	}

	is4, is6 := supportsIPVersions(c.nb.NodeBackend().Self())
	if is4 == nil && is6 == nil {
		return nil
	}
	addrFor := addrPicker(is4, is6)

	var r Report
	for _, n := range nm.Peers {
		if !n.Online().Get() {
			continue // Not connected to the control plane.
		}

		addr := addrFor(n)
		if !addr.IsValid() {
			continue // No valid addresses.
		}

		mak.Set(&r.Reachable, n.ID(), Node{
			ID:     n.ID(),
			Name:   n.Name(),
			Addr:   addr,
			Routes: routes(n),
		})
	}
	r.Done = time.Now()
	return &r
}

// Close immediately stops all active probes.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	close(c.needsRefresh)
	if c.stop != nil {
		c.stop()
	}
	return nil
}
