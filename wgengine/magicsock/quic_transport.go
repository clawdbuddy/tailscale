// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/clawdbuddy/wireguard-go/conn"
	"github.com/quic-go/quic-go"

	"tailscale.com/envknob"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// isQUICClosingErr reports whether err is a QUIC-level close error
// that should terminate the session read loop.
func isQUICClosingErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}
	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		return true
	}
	var statResetErr *quic.StatelessResetError
	if errors.As(err, &statResetErr) {
		return true
	}
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return true
	}
	return false
}

const (
	quicPortOffset        = 1
	quicIdleTimeout       = 5 * time.Minute
	quicKeepAlive         = 30 * time.Second
	quicDialTimeout       = 10 * time.Second
	quicRecvBufSize       = 256
	// quicNoProgressTimeout is the maximum time a QUIC session can go without
	// receiving any datagram or handshake stream from the peer before sendToPeer
	// considers it stale and returns errQUICSessionClosed to trigger UDP fallback.
	// Why: quic-go's Send* APIs succeed once the packet enters the local socket,
	// so application-layer failures (peer not running QUIC, key mismatch, etc.)
	// never surface as send errors. Without an independent liveness signal, the
	// caller cannot tell that the path is dead and never falls back.
	quicNoProgressTimeout = 5 * time.Second
	// quicBlockDuration is how long sendToPeer refuses to re-dial QUIC for a
	// peer after detecting a stale path. Without this, every outbound packet
	// would dial a new session, waste another quicNoProgressTimeout window
	// dropping packets to a dead peer, then fall back again — meaning only one
	// packet per cycle actually reaches the peer over UDP.
	quicBlockDuration = 30 * time.Second
)

var quicTransportEnabled = envknob.RegisterBool("TS_QUIC_TRANSPORT")

var (
	errQUICSessionClosed = errors.New("QUIC session closed")
	errQUICNotEnabled    = errors.New("QUIC transport not enabled")
)

type quicSession struct {
	conn      quic.Connection
	pubKey    key.NodePublic
	closeOnce sync.Once
	done      chan struct{}
}

func (s *quicSession) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.conn != nil {
			s.conn.CloseWithError(0, "closing")
		}
	})
}

type quicPacket struct {
	data []byte
	ep   *endpoint
}

type quicTransport struct {
	mu         sync.Mutex
	listener   *quic.Listener
	qTransport *quic.Transport
	udpConn    *net.UDPConn
	port       uint16

	sessions map[key.NodePublic]*quicSession

	// progressMu guards lastProgress and blockedUntil.
	// lastProgress tracks the last time a datagram or handshake was successfully
	// received from each peer. Used by sendToPeer to detect stale sessions.
	// blockedUntil suppresses new QUIC dials to a peer after a stale event so
	// that endpoint.send keeps using UDP fallback instead of cycling.
	progressMu   sync.Mutex
	lastProgress map[key.NodePublic]time.Time
	blockedUntil map[key.NodePublic]time.Time

	handshakeCh chan quicPacket
	transportCh chan quicPacket

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	conn   *Conn
	closed bool

	droppedTransports atomic.Int64
	droppedHandshakes atomic.Int64
	dropLogged        sync.Once
}

func newQUICTransport(c *Conn, wgPort uint16) (*quicTransport, error) {
	if !quicTransportEnabled() {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	qt := &quicTransport{
		sessions:     make(map[key.NodePublic]*quicSession),
		lastProgress: make(map[key.NodePublic]time.Time),
		blockedUntil: make(map[key.NodePublic]time.Time),
		handshakeCh:  make(chan quicPacket, quicRecvBufSize),
		transportCh:  make(chan quicPacket, quicRecvBufSize),
		tlsConfig:    newQUICTLSConfig(),
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: quicDialTimeout,
			MaxIdleTimeout:       quicIdleTimeout,
			KeepAlivePeriod:      quicKeepAlive,
			MaxIncomingStreams:   64,
			EnableDatagrams:      true,
		},
		ctx:    ctx,
		cancel: cancel,
		conn:   c,
	}

	quicPort := wgPort + quicPortOffset
	if wgPort == 0 {
		quicPort = 0
	}
	addr := netip.AddrPortFrom(netip.IPv6Unspecified(), quicPort)
	udpAddr := net.UDPAddrFromAddrPort(addr)

	udpConn, err := net.ListenUDP(udpAddr.Network(), udpAddr)
	if err != nil {
		cancel()
		return nil, err
	}
	qt.udpConn = udpConn
	qt.port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	qt.qTransport = &quic.Transport{Conn: udpConn}

	ln, err := qt.qTransport.Listen(qt.tlsConfig, qt.quicConfig)
	if err != nil {
		udpConn.Close()
		cancel()
		return nil, err
	}
	qt.listener = ln

	qt.wg.Add(1)
	go qt.acceptLoop()

	return qt, nil
}

func (qt *quicTransport) Close() {
	if qt == nil {
		return
	}

	qt.mu.Lock()
	if qt.closed {
		qt.mu.Unlock()
		return
	}
	qt.closed = true
	sessions := make([]*quicSession, 0, len(qt.sessions))
	for _, s := range qt.sessions {
		sessions = append(sessions, s)
	}
	qt.mu.Unlock()

	qt.cancel()

	for _, s := range sessions {
		s.Close()
	}

	qt.wg.Wait()

	qt.mu.Lock()
	qt.sessions = make(map[key.NodePublic]*quicSession)
	qt.mu.Unlock()

	qt.progressMu.Lock()
	qt.lastProgress = make(map[key.NodePublic]time.Time)
	qt.blockedUntil = make(map[key.NodePublic]time.Time)
	qt.progressMu.Unlock()

	if qt.listener != nil {
		qt.listener.Close()
	}
	if qt.qTransport != nil {
		qt.qTransport.Close()
	}
	if qt.udpConn != nil {
		qt.udpConn.Close()
	}
}

func (qt *quicTransport) acceptLoop() {
	defer qt.wg.Done()

	for {
		conn, err := qt.listener.Accept(qt.ctx)
		if err != nil {
			return
		}

		raddr := conn.RemoteAddr()
		udpAddr := raddr.(*net.UDPAddr)
		addrPort := udpAddr.AddrPort()
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())

		session := &quicSession{
			conn: conn,
			done: make(chan struct{}),
		}

		src := addrPort
		qt.conn.logf("magicsock: QUIC acceptLoop from %v", src)

		// Try to find endpoint by source address (adjusting for QUIC port =
		// wgPort+1). The session MUST be bound to the peer's pubKey here:
		// streamReader and sessionReadLoop deliver received packets to
		// wireguard-go keyed on session.pubKey, and WireGuard handshake
		// messages do not carry the long-term pubKey in plaintext (Initiation
		// encrypts it, Response only has 4-byte indices), so we cannot recover
		// the binding from the message later. If we cannot identify the peer
		// here, the session is useless and we close it.
		ep := qt.conn.findOrCreateEndpointForQUIC(src)
		if ep == nil {
			qt.conn.logf("magicsock: QUIC acceptLoop from %v: no endpoint for source (peerMap has no wgPort=%d); closing session", src, src.Port()-1)
			conn.CloseWithError(0, "unknown peer")
			continue
		}
		session.pubKey = ep.publicKey
		qt.mu.Lock()
		qt.sessions[ep.publicKey] = session
		qt.mu.Unlock()
		// Start the no-progress timer for this peer so sendToPeer can detect
		// a stale path and fall back to UDP. We use seedTimer (not
		// markProgress) because handshake completion alone doesn't prove
		// a working data path — wait for real RX before clearing blockedUntil.
		qt.seedTimer(ep.publicKey)

		qt.wg.Add(1)
		go qt.sessionReadLoop(session, ep)
	}
}

func (qt *quicTransport) dialSession(pubKey key.NodePublic, addr netip.AddrPort) (*quicSession, error) {
	qt.conn.logf("magicsock: QUIC dialSession %s -> %v", pubKey.ShortString(), addr)
	ctx, cancel := context.WithTimeout(qt.ctx, quicDialTimeout)
	defer cancel()

	quicAddr := netip.AddrPortFrom(addr.Addr(), addr.Port()+quicPortOffset)
	udpAddr := net.UDPAddrFromAddrPort(quicAddr)
	conn, err := qt.qTransport.Dial(ctx, udpAddr, qt.tlsConfig, qt.quicConfig)
	if err != nil {
		qt.conn.logf("magicsock: QUIC dialSession %s failed: %v", pubKey.ShortString(), err)
		return nil, err
	}
	qt.conn.logf("magicsock: QUIC dialSession %s -> %v connected", pubKey.ShortString(), quicAddr)

	session := &quicSession{
		conn:   conn,
		pubKey: pubKey,
		done:   make(chan struct{}),
	}

	qt.mu.Lock()
	qt.sessions[pubKey] = session
	qt.mu.Unlock()
	// Start the no-progress timer on dial. If no datagram or handshake arrives
	// within quicNoProgressTimeout, sendToPeer will tear this session down and
	// signal endpoint.send to fall back to UDP.
	qt.seedTimer(pubKey)

	qt.wg.Add(1)
	go qt.sessionReadLoop(session, nil)

	return session, nil
}

func (qt *quicTransport) getOrCreateSession(pubKey key.NodePublic, addr netip.AddrPort) (*quicSession, error) {
	qt.mu.Lock()
	if s, ok := qt.sessions[pubKey]; ok {
		qt.mu.Unlock()
		return s, nil
	}
	qt.mu.Unlock()

	// Dial without holding lock; another goroutine may have created
	// a session while we were unlocked.
	qt.conn.logf("magicsock: QUIC getOrCreateSession dialing %s -> %v", pubKey.ShortString(), addr)
	session, err := qt.dialSession(pubKey, addr)
	if err != nil {
		return nil, err
	}

	// dialSession already added the session to qt.sessions[pubKey].
	// Check whether another goroutine created a session first and
	// if so, close our extra one.
	qt.mu.Lock()
	if existing, ok := qt.sessions[pubKey]; ok && existing != session {
		session.Close()
		qt.mu.Unlock()
		return existing, nil
	}
	qt.mu.Unlock()
	return session, nil
}

func (qt *quicTransport) resolveEndpointByKey(pubKey key.NodePublic) *endpoint {
	qt.conn.mu.Lock()
	defer qt.conn.mu.Unlock()
	e, ok := qt.conn.peerMap.endpointForNodeKey(pubKey)
	if !ok {
		qt.conn.logf("magicsock: QUIC resolveEndpointByKey %s not found in peerMap", pubKey.ShortString())
		return nil
	}
	qt.conn.logf("magicsock: QUIC resolveEndpointByKey %s found endpoint %s", pubKey.ShortString(), e.publicKey.ShortString())
	return e
}

func (qt *quicTransport) sessionReadLoop(session *quicSession, ep *endpoint) {
	defer qt.wg.Done()
	qt.conn.logf("magicsock: QUIC sessionReadLoop start for %s", session.pubKey.ShortString())

	streamCtx, streamCancel := context.WithCancel(qt.ctx)
	defer streamCancel()

	go qt.streamReader(session, streamCtx, ep)

	for {
		data, err := session.conn.ReceiveDatagram(qt.ctx)
		if err != nil {
			qt.conn.logf("magicsock: QUIC sessionReadLoop %s ReceiveDatagram err: %v", session.pubKey.ShortString(), err)
			if isQUICClosingErr(err) {
				return
			}
			select {
			case <-qt.ctx.Done():
				return
			default:
				continue
			}
		}

		msg := make([]byte, len(data))
		copy(msg, data)
		qt.conn.logf("magicsock: QUIC sessionReadLoop %s received datagram len=%d", session.pubKey.ShortString(), len(msg))

		if ep == nil {
			ep = qt.resolveEndpointByKey(session.pubKey)
		}
		if ep == nil {
			continue
		}

		pkt := quicPacket{data: msg, ep: ep}
		select {
		case qt.transportCh <- pkt:
			qt.markProgress(session.pubKey)
			qt.conn.logf("magicsock: QUIC sessionReadLoop %s sent to transportCh", session.pubKey.ShortString())
		default:
			qt.droppedTransports.Add(1)
			qt.conn.logf("magicsock: QUIC sessionReadLoop %s transportCh full, dropping", session.pubKey.ShortString())
			qt.logFirstDrop()
		}
	}
}

func (qt *quicTransport) streamReader(session *quicSession, ctx context.Context, ep *endpoint) {
	qt.conn.logf("magicsock: QUIC streamReader start for %s", session.pubKey.ShortString())
	for {
		stream, err := session.conn.AcceptUniStream(ctx)
		if err != nil {
			qt.conn.logf("magicsock: QUIC streamReader %s AcceptUniStream err: %v", session.pubKey.ShortString(), err)
			return
		}

		go func(s quic.ReceiveStream) {
			defer s.CancelRead(0)

			data, err := io.ReadAll(s)
			if err != nil || len(data) == 0 {
				return
			}
			qt.conn.logf("magicsock: QUIC streamReader %s received stream len=%d", session.pubKey.ShortString(), len(data))

			msg := make([]byte, len(data))
			copy(msg, data)
			qt.conn.logf("magicsock: QUIC streamReader %s raw msg bytes: %x", session.pubKey.ShortString(), msg[:min(32, len(msg))])

			// We previously tried to recover the peer's long-term pubKey from
			// the WireGuard message contents, but that is fundamentally
			// impossible: Initiation's Static field is ChaCha20Poly1305
			// ciphertext, and Response's only fixed fields are 4-byte sender/
			// receiver indices — neither carries the 32-byte pubKey. The
			// session MUST be bound to the right pubKey at accept/dial time
			// (see acceptLoop and dialSession); if it isn't, we have no way
			// to deliver the packet, so drop it.
			if session.pubKey.IsZero() {
				qt.conn.logf("magicsock: QUIC streamReader dropping msg type=%d len=%d: session has no pubKey binding", msg[0], len(msg))
				return
			}

			currentEP := ep
			if currentEP == nil {
				currentEP = qt.resolveEndpointByKey(session.pubKey)
			}
			if currentEP == nil {
				qt.conn.logf("magicsock: QUIC streamReader %s cannot resolve endpoint (msg type %d); dropping", session.pubKey.ShortString(), msg[0])
				return
			}

			select {
			case qt.handshakeCh <- quicPacket{data: msg, ep: currentEP}:
				qt.markProgress(session.pubKey)
				qt.conn.logf("magicsock: QUIC streamReader %s sent to handshakeCh", session.pubKey.ShortString())
			default:
				qt.droppedHandshakes.Add(1)
				qt.conn.logf("magicsock: QUIC streamReader %s handshakeCh full, dropping", session.pubKey.ShortString())
				qt.logFirstDrop()
			}
		}(stream)
	}
}

func (qt *quicTransport) sendToPeer(pubKey key.NodePublic, wgAddr netip.AddrPort, buffs [][]byte, offset int) error {
	qt.conn.logf("magicsock: QUIC sendToPeer %s -> %v, %d buffers", pubKey.ShortString(), wgAddr, len(buffs))

	// Fast path: if we recently marked this peer's QUIC path as dead, skip
	// dialing entirely and let endpoint.send fall back to UDP. Without this,
	// every outbound packet would trigger a fresh dial + 5s grace window of
	// silently dropped packets before the next stale-trigger fired.
	if qt.isBlocked(pubKey) {
		qt.conn.logf("magicsock: QUIC sendToPeer %s blocked; returning errQUICSessionClosed", pubKey.ShortString())
		return errQUICSessionClosed
	}

	// Detect a stale session before reusing it. quic-go reports success the
	// moment a packet enters the local socket, so application-layer failures
	// (peer not running QUIC, key mismatch, etc.) never surface as send errors.
	// If we've sent into this session but received nothing back for longer than
	// quicNoProgressTimeout, treat the path as dead, tear it down, mark the
	// peer blocked, and signal endpoint.send to fall back to UDP via
	// errQUICSessionClosed.
	qt.mu.Lock()
	if s, ok := qt.sessions[pubKey]; ok && qt.isStale(pubKey) {
		delete(qt.sessions, pubKey)
		qt.mu.Unlock()
		qt.markBlocked(pubKey)
		s.Close()
		qt.conn.logf("magicsock: QUIC sendToPeer %s session stale (no rx for >%v); marking blocked for %v, falling back to UDP", pubKey.ShortString(), quicNoProgressTimeout, quicBlockDuration)
		return errQUICSessionClosed
	}
	qt.mu.Unlock()

	session, err := qt.getOrCreateSession(pubKey, wgAddr)
	if err != nil {
		qt.conn.logf("magicsock: QUIC sendToPeer getOrCreateSession failed: %v", err)
		return err
	}

	select {
	case <-session.done:
		qt.mu.Lock()
		delete(qt.sessions, pubKey)
		qt.mu.Unlock()
		qt.conn.logf("magicsock: QUIC sendToPeer session closed, waiting before re-dial")
		time.Sleep(500 * time.Millisecond) // Wait for peer to set up endpoint
		session, err = qt.dialSession(pubKey, wgAddr)
		if err != nil {
			qt.conn.logf("magicsock: QUIC sendToPeer re-dial failed: %v", err)
			return err
		}
	default:
	}

	for _, buf := range buffs {
		if len(buf) <= offset {
			continue
		}
		msg := buf[offset:]
		if len(msg) == 0 {
			continue
		}

		msgType := msg[0]

		switch {
		case msgType >= conn.MessageInitiationType && msgType <= conn.MessageCookieReplyType:
			qt.conn.logf("magicsock: QUIC sendToPeer %s sending handshake (type=%d)", pubKey.ShortString(), msgType)
			if err := qt.sendHandshake(session, msg); err != nil {
				qt.conn.logf("magicsock: QUIC sendToPeer handshake failed: %v", err)
				return err
			}
		case msgType == conn.MessageTransportType:
			qt.conn.logf("magicsock: QUIC sendToPeer %s sending datagram (type=%d, len=%d)", pubKey.ShortString(), msgType, len(msg))
			if err := session.conn.SendDatagram(msg); err != nil {
				qt.conn.logf("magicsock: QUIC sendToPeer datagram failed: %v", err)
				return err
			}
		}
	}

	return nil
}

// markProgress records that a real datagram or handshake stream was received
// from pubKey. It refreshes the no-progress timer and clears any QUIC-block on
// pubKey (real RX is proof that the path is alive again).
func (qt *quicTransport) markProgress(pubKey key.NodePublic) {
	if pubKey.IsZero() {
		return
	}
	qt.progressMu.Lock()
	qt.lastProgress[pubKey] = time.Now()
	delete(qt.blockedUntil, pubKey)
	qt.progressMu.Unlock()
}

// seedTimer starts the no-progress timer for pubKey at "now". Called when a
// session is established (dial or accept). Unlike markProgress, this does NOT
// clear blockedUntil — session establishment alone does not prove a working
// data path.
func (qt *quicTransport) seedTimer(pubKey key.NodePublic) {
	if pubKey.IsZero() {
		return
	}
	qt.progressMu.Lock()
	qt.lastProgress[pubKey] = time.Now()
	qt.progressMu.Unlock()
}

// markBlocked records that pubKey's QUIC path is dead. Subsequent sendToPeer
// calls will short-circuit to errQUICSessionClosed until quicBlockDuration has
// elapsed. Also clears lastProgress so a future re-dial starts with a fresh
// grace period.
func (qt *quicTransport) markBlocked(pubKey key.NodePublic) {
	if pubKey.IsZero() {
		return
	}
	qt.progressMu.Lock()
	qt.blockedUntil[pubKey] = time.Now().Add(quicBlockDuration)
	delete(qt.lastProgress, pubKey)
	qt.progressMu.Unlock()
}

// isBlocked reports whether pubKey is currently in a QUIC fallback window.
// Expired entries are cleaned up opportunistically.
func (qt *quicTransport) isBlocked(pubKey key.NodePublic) bool {
	qt.progressMu.Lock()
	defer qt.progressMu.Unlock()
	t, ok := qt.blockedUntil[pubKey]
	if !ok {
		return false
	}
	if time.Now().Before(t) {
		return true
	}
	delete(qt.blockedUntil, pubKey)
	return false
}

// isStale reports whether the most recent successful receive from pubKey is
// older than quicNoProgressTimeout. Returns false if no progress has ever been
// recorded.
func (qt *quicTransport) isStale(pubKey key.NodePublic) bool {
	qt.progressMu.Lock()
	defer qt.progressMu.Unlock()
	t, ok := qt.lastProgress[pubKey]
	if !ok {
		return false
	}
	return time.Since(t) > quicNoProgressTimeout
}

// clearProgress removes any progress/block entries for pubKey. Called when a
// peer leaves the netmap.
func (qt *quicTransport) clearProgress(pubKey key.NodePublic) {
	qt.progressMu.Lock()
	delete(qt.lastProgress, pubKey)
	delete(qt.blockedUntil, pubKey)
	qt.progressMu.Unlock()
}

// RemovePeerSessions closes and removes QUIC sessions for peers not in the
// given set of node keys. Called from updateNodes during a network map update.
func (qt *quicTransport) RemovePeerSessions(keep set.Set[key.NodePublic]) {
	if qt == nil || !qt.Enabled() {
		return
	}
	var toClose []*quicSession
	var removedKeys []key.NodePublic
	qt.mu.Lock()
	for pk, s := range qt.sessions {
		if !keep.Contains(pk) {
			delete(qt.sessions, pk)
			toClose = append(toClose, s)
			removedKeys = append(removedKeys, pk)
		}
	}
	qt.mu.Unlock()
	qt.progressMu.Lock()
	for _, pk := range removedKeys {
		delete(qt.lastProgress, pk)
		delete(qt.blockedUntil, pk)
	}
	qt.progressMu.Unlock()
	for _, s := range toClose {
		s.Close()
	}
}

// RemovePeerByKey closes and removes the QUIC session for a single peer.
func (qt *quicTransport) RemovePeerByKey(pk key.NodePublic) {
	if qt == nil || !qt.Enabled() {
		return
	}
	qt.mu.Lock()
	s, ok := qt.sessions[pk]
	if ok {
		delete(qt.sessions, pk)
	}
	qt.mu.Unlock()
	qt.clearProgress(pk)
	if ok {
		s.Close()
	}
}

// Rebind closes and re-creates the QUIC listener and UDP socket. If wgPort is
// non-zero, the QUIC port is set to wgPort+quicPortOffset. All existing
// sessions are closed and will be re-established lazily via auto-reconnect.
// Called when the parent magicsock Conn rebinds its UDP sockets (e.g. after a
// network error or interface change).
func (qt *quicTransport) Rebind(wgPort uint16) {
	if qt == nil || !qt.Enabled() || qt.closed {
		return
	}

	if wgPort != 0 {
		qt.port = wgPort + quicPortOffset
	} else if qt.port == 0 {
		// With wgPort==0 the OS assigned the port, keep using it.
	}

	qt.conn.logf("magicsock: QUIC transport rebinding")

	// Close the listener to unblock acceptLoop.
	if qt.listener != nil {
		qt.listener.Close()
	}

	// Close all existing sessions and clear the receive channels.
	qt.mu.Lock()
	sessions := make([]*quicSession, 0, len(qt.sessions))
	for _, s := range qt.sessions {
		sessions = append(sessions, s)
	}
	qt.sessions = make(map[key.NodePublic]*quicSession)
	qt.mu.Unlock()

	qt.progressMu.Lock()
	qt.lastProgress = make(map[key.NodePublic]time.Time)
	qt.blockedUntil = make(map[key.NodePublic]time.Time)
	qt.progressMu.Unlock()

	for _, s := range sessions {
		s.Close()
	}

	// Drain the receive channels to prevent stale packets.
	// This is safe because all senders (sessionReadLoop, streamReader) have been
	// stopped via qt.wg.Wait() below.
	for {
		select {
		case <-qt.handshakeCh:
		default:
			goto drainTransport
		}
	}
drainTransport:
	for {
		select {
		case <-qt.transportCh:
		default:
			goto doneDraining
		}
	}
doneDraining:

	// Wait for acceptLoop and sessionReadLoops to finish.
	qt.wg.Wait()

	// Close old transport and UDP conn.
	if qt.qTransport != nil {
		qt.qTransport.Close()
		qt.qTransport = nil
	}
	if qt.udpConn != nil {
		qt.udpConn.Close()
		qt.udpConn = nil
	}

	// Re-create UDP socket on the same port.
	addr := netip.AddrPortFrom(netip.IPv6Unspecified(), qt.port)
	udpAddr := net.UDPAddrFromAddrPort(addr)
	udpConn, err := net.ListenUDP(udpAddr.Network(), udpAddr)
	if err != nil {
		qt.conn.logf("magicsock: QUIC rebind: listen failed on %v: %v", addr, err)
		return
	}
	qt.udpConn = udpConn
	qt.port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	qt.qTransport = &quic.Transport{Conn: udpConn}

	// Re-create QUIC listener.
	ln, err := qt.qTransport.Listen(qt.tlsConfig, qt.quicConfig)
	if err != nil {
		qt.conn.logf("magicsock: QUIC rebind: listen failed: %v", err)
		// Don't leave transport in broken state: keep the UDP socket bound.
		// The old port is preserved in qt.port for the next Rebind attempt.
		qt.listener = nil
		return
	}
	qt.listener = ln

	// Restart accept loop.
	qt.wg.Add(1)
	go qt.acceptLoop()

	qt.conn.logf("magicsock: QUIC transport rebound on port %d", qt.port)
}

func (qt *quicTransport) sendHandshake(session *quicSession, msg []byte) error {
	ctx, cancel := context.WithTimeout(qt.ctx, quicDialTimeout)
	defer cancel()

	stream, err := session.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}

	if _, err := stream.Write(msg); err != nil {
		stream.Close()
		return err
	}

	return stream.Close()
}

func (qt *quicTransport) receiveHandshake() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i := range packets {
			packets[i] = packets[i][:cap(packets[i])]
		}

		select {
		case pkt, ok := <-qt.handshakeCh:
			if !ok {
				return 0, net.ErrClosed
			}
			n := copy(packets[0], pkt.data)
			sizes[0] = n
			eps[0] = pkt.ep

			count := 1
			for i := 1; i < len(packets); i++ {
				select {
				case pkt, ok := <-qt.handshakeCh:
					if !ok {
						return count, nil
					}
					n := copy(packets[i], pkt.data)
					sizes[i] = n
					eps[i] = pkt.ep
					count++
				default:
					return count, nil
				}
			}
			return count, nil

		case <-qt.ctx.Done():
			return 0, net.ErrClosed
		}
	}
}

func (qt *quicTransport) receiveTransport() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i := range packets {
			packets[i] = packets[i][:cap(packets[i])]
		}

		select {
		case pkt, ok := <-qt.transportCh:
			if !ok {
				return 0, net.ErrClosed
			}
			n := copy(packets[0], pkt.data)
			sizes[0] = n
			eps[0] = pkt.ep

			count := 1
			for i := 1; i < len(packets); i++ {
				select {
				case pkt, ok := <-qt.transportCh:
					if !ok {
						return count, nil
					}
					n := copy(packets[i], pkt.data)
					sizes[i] = n
					eps[i] = pkt.ep
					count++
				default:
					return count, nil
				}
			}
			return count, nil

		case <-qt.ctx.Done():
			return 0, net.ErrClosed
		}
	}
}

func (qt *quicTransport) LocalPort() uint16 {
	if qt == nil {
		return 0
	}
	return qt.port
}

func (qt *quicTransport) Type() string {
	if qt == nil {
		return "none"
	}
	return "QUIC"
}

func (qt *quicTransport) Enabled() bool {
	return qt != nil && !qt.closed
}

func (qt *quicTransport) logFirstDrop() {
	qt.dropLogged.Do(func() {
		qt.conn.logf("magicsock: QUIC receive channel full, dropping packets")
	})
}

func (qt *quicTransport) Stats() (droppedTransports, droppedHandshakes int64) {
	return qt.droppedTransports.Load(), qt.droppedHandshakes.Load()
}

func newQUICTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"wireguard-quic"},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}
}
