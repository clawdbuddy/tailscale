// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
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

// quicHeaderLen returns the QUIC header length for a WireGuard message,
// or 0 if the message type is unknown (not WireGuard).
func quicHeaderLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	msgType := b[0]
	switch {
	case msgType >= conn.MessageInitiationType && msgType <= conn.MessageCookieReplyType:
		return quicLongHdrLen
	case msgType == conn.MessageTransportType:
		return quicShortHdrLen
	default:
		return 0
	}
}

// prependQUICHeader prepends a QUIC-like header to a WireGuard packet.
// It returns a new slice containing the QUIC header followed by the WireGuard payload.
// The input b is not modified.
func prependQUICHeader(b []byte, cid [8]byte) []byte {
	hdrLen := quicHeaderLen(b)
	if hdrLen == 0 {
		return b
	}

	msgType := b[0]
	out := make([]byte, hdrLen+len(b))

	if msgType >= conn.MessageInitiationType && msgType <= conn.MessageCookieReplyType {
		out[0] = 0xC0 | 0x01
		binary.BigEndian.PutUint32(out[1:5], 1)
		out[5] = quicCIDLength
		copy(out[6:14], cid[:])
		out[14] = 0
		counter := binary.LittleEndian.Uint64(b[8:])
		binary.LittleEndian.PutUint16(out[15:], uint16(counter))
	} else {
		out[0] = 0x40
		copy(out[1:9], cid[:])
		counter := binary.LittleEndian.Uint64(b[8:])
		binary.LittleEndian.PutUint16(out[9:], uint16(counter))
	}

	copy(out[hdrLen:], b)
	return out
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

// quicLogLimit limits QUIC obfuscation log messages to avoid spam.
var quicLogLimit = func() func() bool {
	var mu sync.Mutex
	var count int
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		count++
		if count <= 3 || count%100 == 0 {
			return true
		}
		return false
	}
}()

func logQUIC(format string, args ...any) {
	if quicLogLimit() {
		log.Printf(format, args...)
	}
}
