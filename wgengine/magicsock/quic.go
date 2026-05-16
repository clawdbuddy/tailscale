// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/clawdbuddy/wireguard-go/conn"
	"tailscale.com/envknob"
)

const (
	geneveFixedHdrLen = 8
	quicCIDLength     = 8
	quicShortHdrLen   = 11
	quicLongHdrLen    = 17
)

var quicObfuscationTS = envknob.RegisterBool("TS_QUIC_OBFUSCATION")
var quicObfuscationWG = envknob.RegisterBool("WG_QUIC_OBFUSCATION")

func quicObfuscationEnabled() bool {
	return quicObfuscationTS() || quicObfuscationWG()
}

// quicState holds per-connection QUIC obfuscation state.
type quicState struct {
	quicObfuscation atomic.Bool

	connectionIDs   map[string][8]byte
	connectionIDsMu sync.RWMutex
}

func newQUICState() *quicState {
	return &quicState{
		connectionIDs: make(map[string][8]byte),
	}
}

// deriveQUICConnectionID derives an 8-byte QUIC connection ID from an endpoint.
func deriveQUICConnectionID(ep conn.Endpoint) [8]byte {
	return deriveQUICConnectionIDFromBytes(ep.DstToBytes())
}

func deriveQUICConnectionIDFromBytes(dst []byte) [8]byte {
	h := sha256.Sum256(dst)
	var cid [8]byte
	copy(cid[:], h[:8])
	return cid
}

func (qs *quicState) getConnectionID(ep conn.Endpoint) [8]byte {
	addr := ep.DstToString()
	qs.connectionIDsMu.RLock()
	cid, ok := qs.connectionIDs[addr]
	qs.connectionIDsMu.RUnlock()
	if ok {
		return cid
	}
	cid = deriveQUICConnectionID(ep)
	qs.connectionIDsMu.Lock()
	qs.connectionIDs[addr] = cid
	qs.connectionIDsMu.Unlock()
	return cid
}

// stripQUICHeader strips a QUIC-like header from a packet in-place.
// It returns the size of the stripped packet (WireGuard data) and true if
// a QUIC header was found and stripped. If no header is detected, it
// returns the original size and false.
func stripQUICHeader(b []byte, size int) (int, bool) {
	if size < 1 {
		return size, false
	}

	firstByte := b[0]
	var quicHdrLen int
	if (firstByte & 0x80) != 0 {
		quicHdrLen = quicLongHdrLen
	} else if (firstByte & 0x40) != 0 {
		quicHdrLen = quicShortHdrLen
	} else {
		return size, false
	}

	if size <= quicHdrLen {
		return size, false
	}

	wgLen := size - quicHdrLen
	copy(b[:wgLen], b[quicHdrLen:size])
	return wgLen, true
}

// wrapQUICPacket wraps a raw buffer (with offset leading space) in-place,
// moving the data and writing a QUIC header at position 0.
// It returns the total packet length (QUIC header + WireGuard data).
// The buffer must have at least quicHdrLen + wgLen bytes capacity.
func wrapQUICPacket(buf []byte, offset int, cid [8]byte) int {
	if offset != geneveFixedHdrLen || len(buf) < offset {
		return len(buf)
	}

	msgType := buf[offset]
	var hdrLen int
	switch {
	case msgType >= conn.MessageInitiationType && msgType <= conn.MessageCookieReplyType:
		hdrLen = quicLongHdrLen
	case msgType == conn.MessageTransportType:
		hdrLen = quicShortHdrLen
	default:
		return len(buf)
	}

	wgLen := len(buf) - offset

	// 如果 buffer capacity 不足以容纳 QUIC header + WG payload，
	// 回退为发送裸 WireGuard 包（不包装 QUIC header）。
	// 裸 WG 包首字节为 1-4，接收端 stripQUICHeader 不会误剥离。
	if cap(buf) < hdrLen+wgLen {
		return offset + wgLen
	}

	counter := binary.LittleEndian.Uint64(buf[offset+8:])

	copy(buf[hdrLen:hdrLen+wgLen], buf[offset:offset+wgLen])

	if msgType >= conn.MessageInitiationType && msgType <= conn.MessageCookieReplyType {
		buf[0] = 0xC0 | 0x01
		binary.BigEndian.PutUint32(buf[1:5], 1)
		buf[5] = quicCIDLength
		copy(buf[6:14], cid[:])
		buf[14] = 0
		binary.LittleEndian.PutUint16(buf[15:], uint16(counter))
	} else {
		buf[0] = 0x40
		copy(buf[1:9], cid[:])
		binary.LittleEndian.PutUint16(buf[9:], uint16(counter))
	}

	return hdrLen + wgLen
}

// sendQUICDirect sends buffs with QUIC headers prepended to the given UDP address.
// It handles both single-packet and batch-like semantics using the single-packet
// path, since the Geneve/batch path requires a specific data offset.
func (c *Conn) sendQUICDirect(addr netip.AddrPort, buffs [][]byte, offset int, cid [8]byte) error {
	isIPv6 := addr.Addr().Is6()

	for _, buf := range buffs {
		totalLen := wrapQUICPacket(buf, offset, cid)

		var err error
		if isIPv6 {
			_, err = c.pconn6.WriteToUDPAddrPort(buf[:totalLen], addr)
		} else {
			_, err = c.pconn4.WriteToUDPAddrPort(buf[:totalLen], addr)
		}
		if err != nil {
			c.maybeRebindOnError(err)
			return err
		}
	}
	return nil
}


