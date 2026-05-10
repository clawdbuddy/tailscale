// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/clawdbuddy/wireguard-go/device"
	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/net/stun"
	"tailscale.com/types/key"
)

// TestStripQUICHeaderPreservesNonWireGuard guards against regressions where
// stripQUICHeader misidentifies non-WireGuard UDP traffic as a QUIC short
// header and removes 11 bytes from the front of the packet.
//
// The disco magic ("TS💬") starts with 0x54, whose 0x40 bit is set; a naive
// `firstByte & 0x40 != 0` check classifies disco as QUIC short header and
// destroys the magic, breaking direct connection negotiation entirely when
// QUIC obfuscation is enabled.
func TestStripQUICHeaderPreservesNonWireGuard(t *testing.T) {
	discoPub := key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 30: 30, 31: 31}))
	nakedDisco := make([]byte, 0, 128)
	nakedDisco = append(nakedDisco, disco.Magic...)
	nakedDisco = discoPub.AppendTo(nakedDisco)
	// Pad to a length that exceeds the QUIC short header (11 bytes) so the
	// strip would actually run if the bug were present.
	nakedDisco = append(nakedDisco, bytes.Repeat([]byte{0xAB}, 64)...)

	stunResp := stun.Response(stun.NewTxID(), netip.MustParseAddrPort("127.0.0.1:1"))

	// Build a valid wrapped QUIC short-header WG transport packet.
	wgTransport := make([]byte, 32)
	wgTransport[0] = device.MessageTransportType
	binary.LittleEndian.PutUint64(wgTransport[8:], 0xdeadbeef)
	wgTransportWrapped := prependQUICHeader(wgTransport, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Build a valid wrapped QUIC long-header WG initiation packet.
	wgInit := make([]byte, 64)
	wgInit[0] = device.MessageInitiationType
	binary.LittleEndian.PutUint64(wgInit[8:], 0x1234)
	wgInitWrapped := prependQUICHeader(wgInit, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})

	tests := []struct {
		name        string
		input       []byte
		wantStrip   bool
		wantPayload []byte
	}{
		{
			name:        "naked-disco-must-not-be-stripped",
			input:       nakedDisco,
			wantStrip:   false,
			wantPayload: nakedDisco,
		},
		{
			name:        "stun-response-must-not-be-stripped",
			input:       stunResp,
			wantStrip:   false,
			wantPayload: stunResp,
		},
		{
			name:        "wrapped-wg-transport-stripped",
			input:       wgTransportWrapped,
			wantStrip:   true,
			wantPayload: wgTransport,
		},
		{
			name:        "wrapped-wg-initiation-stripped",
			input:       wgInitWrapped,
			wantStrip:   true,
			wantPayload: wgInit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// stripQUICHeader operates on the raw buffer, so we copy the
			// input first to avoid clobbering test fixtures across cases.
			buf := append([]byte(nil), tt.input...)
			if disco.LooksLikeDiscoWrapper(buf) {
				// This mirrors the production guard added in the receive
				// path: disco messages must not be passed to stripQUICHeader.
				if tt.wantStrip {
					t.Fatalf("test setup error: disco buffer marked as expected-strip")
				}
				if !bytes.Equal(buf, tt.wantPayload) {
					t.Fatalf("disco payload mutated unexpectedly")
				}
				return
			}
			n, stripped := stripQUICHeader(buf, len(buf))
			if stripped != tt.wantStrip {
				t.Fatalf("stripped=%v want %v", stripped, tt.wantStrip)
			}
			got := buf[:n]
			if !bytes.Equal(got, tt.wantPayload) {
				t.Fatalf("payload mismatch\n got: %x\nwant: %x", got, tt.wantPayload)
			}
		})
	}
}
