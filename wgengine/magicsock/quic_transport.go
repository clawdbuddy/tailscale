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

const (
	quicPortOffset        = 1
	quicIdleTimeout       = 5 * time.Minute
	quicKeepAlive         = 30 * time.Second
	quicDialTimeout       = 10 * time.Second
	quicRecvBufSize = 256
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
		sessions:    make(map[key.NodePublic]*quicSession),
		handshakeCh: make(chan quicPacket, quicRecvBufSize),
		transportCh: make(chan quicPacket, quicRecvBufSize),
		tlsConfig:   newQUICTLSConfig(),
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
		ep := qt.conn.findOrCreateEndpointForQUIC(src)
		if ep == nil {
			conn.CloseWithError(0, "unknown peer")
			continue
		}

		pk := ep.publicKey
		qt.mu.Lock()
		qt.sessions[pk] = session
		qt.mu.Unlock()

		qt.wg.Add(1)
		go qt.sessionReadLoop(session, ep)
	}
}

func (qt *quicTransport) dialSession(pubKey key.NodePublic, addr netip.AddrPort) (*quicSession, error) {
	ctx, cancel := context.WithTimeout(qt.ctx, quicDialTimeout)
	defer cancel()

	quicAddr := netip.AddrPortFrom(addr.Addr(), addr.Port()+quicPortOffset)
	udpAddr := net.UDPAddrFromAddrPort(quicAddr)
	conn, err := qt.qTransport.Dial(ctx, udpAddr, qt.tlsConfig, qt.quicConfig)
	if err != nil {
		return nil, err
	}

	session := &quicSession{
		conn:   conn,
		pubKey: pubKey,
		done:   make(chan struct{}),
	}

	qt.mu.Lock()
	qt.sessions[pubKey] = session
	qt.mu.Unlock()

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
	session, err := qt.dialSession(pubKey, addr)
	if err != nil {
		return nil, err
	}

	// Check whether another goroutine created a session first.
	qt.mu.Lock()
	if existing, ok := qt.sessions[pubKey]; ok {
		// Another goroutine beat us; close our session and return the existing one.
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
		return nil
	}
	return e
}

func (qt *quicTransport) sessionReadLoop(session *quicSession, ep *endpoint) {
	defer qt.wg.Done()

	streamCtx, streamCancel := context.WithCancel(qt.ctx)
	defer streamCancel()

	go qt.streamReader(session, streamCtx, ep)

	for {
		data, err := session.conn.ReceiveDatagram(qt.ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
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

		if ep == nil {
			ep = qt.resolveEndpointByKey(session.pubKey)
		}
		if ep == nil {
			continue
		}

		pkt := quicPacket{data: msg, ep: ep}
		select {
		case qt.transportCh <- pkt:
		default:
			qt.droppedTransports.Add(1)
			qt.logFirstDrop()
		}
	}
}

func (qt *quicTransport) streamReader(session *quicSession, ctx context.Context, ep *endpoint) {
	for {
		stream, err := session.conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}

		go func(s quic.ReceiveStream) {
			defer s.CancelRead(0)

			data, err := io.ReadAll(s)
			if err != nil || len(data) == 0 {
				return
			}

			msg := make([]byte, len(data))
			copy(msg, data)

			currentEP := ep
			if currentEP == nil {
				currentEP = qt.resolveEndpointByKey(session.pubKey)
			}
			if currentEP == nil {
				return
			}

			select {
			case qt.handshakeCh <- quicPacket{data: msg, ep: currentEP}:
			default:
				qt.droppedHandshakes.Add(1)
				qt.logFirstDrop()
			}
		}(stream)
	}
}

func (qt *quicTransport) sendToPeer(pubKey key.NodePublic, wgAddr netip.AddrPort, buffs [][]byte, offset int) error {
	session, err := qt.getOrCreateSession(pubKey, wgAddr)
	if err != nil {
		return err
	}

	select {
	case <-session.done:
		qt.mu.Lock()
		delete(qt.sessions, pubKey)
		qt.mu.Unlock()
		session, err = qt.dialSession(pubKey, wgAddr)
		if err != nil {
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
			if err := qt.sendHandshake(session, msg); err != nil {
				return err
			}
		case msgType == conn.MessageTransportType:
			if err := session.conn.SendDatagram(msg); err != nil {
				return err
			}
		}
	}

	return nil
}

// RemovePeerSessions closes and removes QUIC sessions for peers not in the
// given set of node keys. Called from updateNodes during a network map update.
func (qt *quicTransport) RemovePeerSessions(keep set.Set[key.NodePublic]) {
	if qt == nil || !qt.Enabled() {
		return
	}
	var toClose []*quicSession
	qt.mu.Lock()
	for pk, s := range qt.sessions {
		if !keep.Contains(pk) {
			delete(qt.sessions, pk)
			toClose = append(toClose, s)
		}
	}
	qt.mu.Unlock()
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
