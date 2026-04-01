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
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
)

var (
	metricRefresh = clientmetric.NewCounter("routecheck_refresh")
)

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
