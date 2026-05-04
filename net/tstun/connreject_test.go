// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"testing"

	"go4.org/netipx"
	"tailscale.com/net/connreject"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine/filter"
)

// TestOutboundTSMPRecordsRejection verifies that when an inbound TCP4 SYN
// is dropped by the packet filter, the TSMP reject we inject outbound is
// also delivered to the connreject note callback.
func TestOutboundTSMPRecordsRejection(t *testing.T) {
	t.Parallel()
	bus := eventbustest.NewBus(t)
	_, w := newFakeTUN(t.Logf, bus, false)
	defer w.Close()

	// The note callback fires synchronously from
	// filterPacketInboundFromWireGuard on this test's goroutine, so a
	// plain slice (no mutex) is sufficient.
	var events []connreject.Event
	w.SetConnRejectNote(func(e connreject.Event) { events = append(events, e) })

	// Drain the outbound queue so InjectOutbound doesn't block.
	go func() {
		var buf [MaxPacketSize]byte
		for {
			n, err := w.Read([][]byte{buf[:]}, []int{0}, 0)
			_ = n
			if err != nil {
				return
			}
		}
	}()

	// Install an allow-none filter so the inbound SYN is dropped,
	// triggering the TSMP reject emission.
	w.disableFilter = false
	w.SetFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))

	pkt := tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000)
	p := new(packet.Parsed)
	p.Decode(pkt)

	if res, _ := w.filterPacketInboundFromWireGuard(p, nil, nil, nil); !res.IsDrop() {
		t.Fatalf("expected drop, got %v", res)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0]
	if got.Direction != connreject.Incoming {
		t.Errorf("Direction = %v, want Incoming", got.Direction)
	}
	if got.Source != connreject.SourceTSMPSent {
		t.Errorf("Source = %v, want tsmp_sent", got.Source)
	}
	if got.Reason != connreject.ReasonACL {
		t.Errorf("Reason = %q, want %q", got.Reason, connreject.ReasonACL)
	}
	if got.Proto != ipproto.TCP {
		t.Errorf("Proto = %v, want TCP", got.Proto)
	}
	// Src is the remote peer-side of the incoming flow.
	if got.Src.Port() != 1234 {
		t.Errorf("Src.Port = %d, want 1234", got.Src.Port())
	}
	if got.Dst.Port() != 60000 {
		t.Errorf("Dst.Port = %d, want 60000", got.Dst.Port())
	}
}

// TestOutboundTSMPNotRecordedWhenDisabled verifies we skip the note
// callback when disableTSMPRejected is set.
func TestOutboundTSMPNotRecordedWhenDisabled(t *testing.T) {
	t.Parallel()
	bus := eventbustest.NewBus(t)
	_, w := newFakeTUN(t.Logf, bus, false)
	defer w.Close()

	var events []connreject.Event
	w.SetConnRejectNote(func(e connreject.Event) { events = append(events, e) })

	w.disableFilter = false
	w.disableTSMPRejected = true
	w.SetFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))

	pkt := tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000)
	p := new(packet.Parsed)
	p.Decode(pkt)

	w.filterPacketInboundFromWireGuard(p, nil, nil, nil)

	if len(events) != 0 {
		t.Errorf("got %d events, want 0 when disableTSMPRejected was set", len(events))
	}
}
