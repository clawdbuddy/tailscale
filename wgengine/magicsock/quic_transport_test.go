// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/clawdbuddy/wireguard-go/conn"
	"github.com/clawdbuddy/wireguard-go/device"
	"github.com/quic-go/quic-go"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

func enableQUICTransport(t *testing.T) {
	envknob.Setenv("TS_QUIC_TRANSPORT", "1")
	t.Cleanup(func() { envknob.Setenv("TS_QUIC_TRANSPORT", "") })
}

func TestQUICTransportNilSafety(t *testing.T) {
	var qt *quicTransport
	if qt.Type() != "none" {
		t.Fatalf("Type() = %q, want none", qt.Type())
	}
	if qt.Enabled() {
		t.Fatal("Enabled() = true, want false")
	}
	if qt.LocalPort() != 0 {
		t.Fatalf("LocalPort() = %d, want 0", qt.LocalPort())
	}
}

func TestQUICTransportNewEnvOff(t *testing.T) {
	envknob.Setenv("TS_QUIC_TRANSPORT", "")
	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport() error = %v", err)
	}
	if qt != nil {
		qt.Close()
		t.Fatal("newQUICTransport() = non-nil, want nil")
	}
}

func TestQUICTransportNewEnvOn(t *testing.T) {
	enableQUICTransport(t)
	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport() error = %v", err)
	}
	if qt == nil {
		t.Fatal("newQUICTransport() = nil, want non-nil")
	}
	t.Cleanup(qt.Close)

	if qt.LocalPort() == 0 {
		t.Fatal("LocalPort() = 0, want non-zero")
	}
	if !qt.Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
	if qt.Type() != "QUIC" {
		t.Fatalf("Type() = %q, want QUIC", qt.Type())
	}
}

func TestQUICTransportSessionCloseIdempotent(t *testing.T) {
	s := &quicSession{
		done: make(chan struct{}),
	}
	s.Close()
	s.Close()
	select {
	case <-s.done:
	default:
		t.Fatal("done channel not closed after Close()")
	}
}

func TestQUICTransportNewTLSConfig(t *testing.T) {
	cfg := newQUICTLSConfig()
	if cfg == nil {
		t.Fatal("newQUICTLSConfig() = nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "wireguard-quic" {
		t.Fatalf("NextProtos = %v, want [wireguard-quic]", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestQUICTransportHandshakeReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	qt := &quicTransport{
		handshakeCh: make(chan quicPacket, quicRecvBufSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	ep := &endpoint{}
	qt.handshakeCh <- quicPacket{data: []byte("hello"), ep: ep}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1024)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := qt.receiveHandshake()(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receiveHandshake() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("receiveHandshake() n = %d, want 1", n)
	}
	if string(packets[0][:sizes[0]]) != "hello" {
		t.Fatalf("payload = %q, want %q", string(packets[0][:sizes[0]]), "hello")
	}
	if eps[0] != ep {
		t.Fatal("endpoint mismatch")
	}
}

func TestQUICTransportTransportReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	qt := &quicTransport{
		transportCh: make(chan quicPacket, quicRecvBufSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	ep := &endpoint{}
	qt.transportCh <- quicPacket{data: []byte("world"), ep: ep}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1024)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := qt.receiveTransport()(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receiveTransport() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("receiveTransport() n = %d, want 1", n)
	}
	if string(packets[0][:sizes[0]]) != "world" {
		t.Fatalf("payload = %q, want %q", string(packets[0][:sizes[0]]), "world")
	}
	if eps[0] != ep {
		t.Fatal("endpoint mismatch")
	}
}

func TestQUICTransportReceiveBatchDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	qt := &quicTransport{
		handshakeCh: make(chan quicPacket, quicRecvBufSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	for i := 0; i < 3; i++ {
		qt.handshakeCh <- quicPacket{data: []byte{byte('a' + i)}, ep: &endpoint{}}
	}

	packets := make([][]byte, 5)
	for i := range packets {
		packets[i] = make([]byte, 1024)
	}
	sizes := make([]int, 5)
	eps := make([]conn.Endpoint, 5)

	n, err := qt.receiveHandshake()(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receiveHandshake() error = %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	for i := 0; i < 3; i++ {
		if sizes[i] != 1 || packets[i][0] != byte('a'+i) {
			t.Fatalf("packet[%d] = %q, want %q", i, string(packets[i][:sizes[i]]), string([]byte{byte('a' + i)}))
		}
	}
}

func TestQUICTransportReceiveCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	qt := &quicTransport{
		handshakeCh: make(chan quicPacket, quicRecvBufSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	cancel()

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1024)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	_, err := qt.receiveHandshake()(packets, sizes, eps)
	if err == nil {
		t.Fatal("receiveHandshake() expected error after cancel")
	}
}

func TestQUICTransportCloseCleanup(t *testing.T) {
	enableQUICTransport(t)
	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport() error = %v", err)
	}
	if qt == nil {
		t.Fatal("newQUICTransport() = nil")
	}

	pk := key.NewNode().Public()
	qt.mu.Lock()
	qt.sessions[pk] = &quicSession{
		conn: nil,
		done: make(chan struct{}),
	}
	qt.mu.Unlock()

	qt.Close()

	if qt.Enabled() {
		t.Fatal("Enabled() = true after Close()")
	}
	qt.mu.Lock()
	if len(qt.sessions) != 0 {
		t.Fatalf("sessions = %d after Close(), want 0", len(qt.sessions))
	}
	qt.mu.Unlock()
}

func TestQUICTransportCloseTwice(t *testing.T) {
	enableQUICTransport(t)
	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport() error = %v", err)
	}
	if qt == nil {
		t.Fatal("newQUICTransport() = nil")
	}
	qt.Close()
	qt.Close()
}

func TestQUICTransportSendToPeerClosedSession(t *testing.T) {
	enableQUICTransport(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	qTransport := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { qTransport.Close() })

	pk := key.NewNode().Public()
	s := &quicSession{
		pubKey: pk,
		done:   make(chan struct{}),
	}
	s.Close()

	qt := &quicTransport{
		sessions:   map[key.NodePublic]*quicSession{pk: s},
		qTransport: qTransport,
		tlsConfig:  newQUICTLSConfig(),

		ctx:    ctx,
		cancel: cancel,
	}

	err = qt.sendToPeer(pk, netip.AddrPort{}, [][]byte{{device.MessageTransportType}}, 0)
	if err == nil {
		t.Fatal("sendToPeer() expected error for closed session (dial should fail)")
	}
}

func TestQUICTransportSendToPeerDeletesClosedSession(t *testing.T) {
	enableQUICTransport(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	qTransport := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { qTransport.Close() })

	pk := key.NewNode().Public()
	s := &quicSession{
		pubKey: pk,
		done:   make(chan struct{}),
	}
	s.Close()

	qt := &quicTransport{
		sessions:   map[key.NodePublic]*quicSession{pk: s},
		qTransport: qTransport,
		tlsConfig:  newQUICTLSConfig(),
		quicConfig: &quic.Config{EnableDatagrams: true},
		ctx:    ctx,
		cancel: cancel,
	}

	_ = qt.sendToPeer(pk, netip.AddrPort{}, [][]byte{{device.MessageTransportType}}, 0)

	qt.mu.Lock()
	_, exists := qt.sessions[pk]
	qt.mu.Unlock()
	if exists {
		t.Fatal("session should be deleted from map after detecting closed session")
	}
}

func TestQUICTransportGetOrCreateSessionReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	qt := &quicTransport{
		sessions: make(map[key.NodePublic]*quicSession),
		ctx:      ctx,
		cancel:   cancel,
	}

	pk := key.NewNode().Public()
	s := &quicSession{
		pubKey: pk,
		done:   make(chan struct{}),
	}
	qt.sessions[pk] = s

	got, err := qt.getOrCreateSession(pk, netip.AddrPort{})
	if err != nil {
		t.Fatalf("getOrCreateSession() error = %v", err)
	}
	if got != s {
		t.Fatal("getOrCreateSession() returned different session")
	}
}

func TestQUICTransportRoundTrip(t *testing.T) {
	enableQUICTransport(t)

	cServer := newConn(t.Logf)
	qtServer, err := newQUICTransport(cServer, 0)
	if err != nil {
		t.Fatalf("newQUICTransport server: %v", err)
	}
	t.Cleanup(qtServer.Close)

	serverQUICPort := qtServer.LocalPort()
	serverPub := key.NewNode().Public()

	cClient := newConn(t.Logf)
	qtClient, err := newQUICTransport(cClient, 0)
	if err != nil {
		t.Fatalf("newQUICTransport client: %v", err)
	}
	t.Cleanup(qtClient.Close)

	clientPort := uint16(qtClient.udpConn.LocalAddr().(*net.UDPAddr).Port)
	clientAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), clientPort)

	clientEP := &endpoint{
		c:         cServer,
		publicKey: serverPub,
	}

	pi := newPeerInfo(clientEP)
	epAddrVal := epAddr{ap: clientAddrPort}
	pi.epAddrs.Add(epAddrVal)

	cServer.mu.Lock()
	cServer.peerMap.byNodeKey[serverPub] = pi
	cServer.peerMap.byEpAddr[epAddrVal] = pi
	cServer.mu.Unlock()

	handshakeMsg := []byte{device.MessageInitiationType, 0x01, 0x02, 0x03}
	transportMsg := []byte{device.MessageTransportType, 0x04, 0x05, 0x06}

	serverWgPort := serverQUICPort - quicPortOffset
	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverWgPort)

	err = qtClient.sendToPeer(serverPub, serverAddr, [][]byte{handshakeMsg}, 0)
	if err != nil {
		t.Fatalf("sendToPeer handshake: %v", err)
	}

	err = qtClient.sendToPeer(serverPub, serverAddr, [][]byte{transportMsg}, 0)
	if err != nil {
		t.Fatalf("sendToPeer transport: %v", err)
	}

	var foundHandshake bool
	for i := 0; i < 100; i++ {
		select {
		case pkt := <-qtServer.handshakeCh:
			if len(pkt.data) > 0 && pkt.data[0] == device.MessageInitiationType {
				foundHandshake = true
			}
		default:
		}
		if foundHandshake {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !foundHandshake {
		t.Fatal("handshake message not received within timeout")
	}

	var foundTransport bool
	for i := 0; i < 100; i++ {
		select {
		case pkt := <-qtServer.transportCh:
			if len(pkt.data) > 0 && pkt.data[0] == device.MessageTransportType {
				foundTransport = true
			}
		default:
		}
		if foundTransport {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !foundTransport {
		t.Fatal("transport message not received within timeout")
	}
}

func TestQUICTransportSTUNPassthrough(t *testing.T) {
	qt := &quicTransport{
		transportCh: make(chan quicPacket, quicRecvBufSize),
		ctx:         context.Background(),
		cancel:      func() {},
	}

	stunResp := stun.Response(stun.NewTxID(), netip.MustParseAddrPort("127.0.0.1:1"))
	qt.transportCh <- quicPacket{data: stunResp, ep: &endpoint{}}

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := qt.receiveTransport()(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receiveTransport() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("receiveTransport() n = %d, want 1", n)
	}
	if sizes[0] != len(stunResp) {
		t.Fatalf("payload size = %d, want %d", sizes[0], len(stunResp))
	}
}

func TestQUICTransportDisabledMethod(t *testing.T) {
	qt := &quicTransport{closed: true}
	if qt.Enabled() {
		t.Fatal("Enabled() should be false when closed")
	}
}

func TestQUICTransportConcurrentSessionAccess(t *testing.T) {
	enableQUICTransport(t)
	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport() error = %v", err)
	}
	t.Cleanup(qt.Close)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pk := key.NewNode().Public()
			qt.mu.Lock()
			qt.sessions[pk] = &quicSession{
				done: make(chan struct{}),
			}
			qt.mu.Unlock()
		}()
	}
	wg.Wait()

	qt.mu.Lock()
	count := len(qt.sessions)
	qt.mu.Unlock()
	if count != 20 {
		t.Fatalf("sessions = %d, want 20", count)
	}
}

func TestQUICTransportTypeString(t *testing.T) {
	tests := []struct {
		name string
		qt   *quicTransport
		want string
	}{
		{"nil", nil, "none"},
		{"closed", &quicTransport{closed: true}, "QUIC"},
		{"active", &quicTransport{}, "QUIC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.qt.Type(); got != tt.want {
				t.Fatalf("Type() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQUICTransportLocalPort(t *testing.T) {
	tests := []struct {
		name string
		qt   *quicTransport
		want uint16
	}{
		{"nil", nil, 0},
		{"zero", &quicTransport{}, 0},
		{"set", &quicTransport{port: 12345}, 12345},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.qt.LocalPort(); got != tt.want {
				t.Fatalf("LocalPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestQUICTransportChannelFullNoBlock(t *testing.T) {
	qt := &quicTransport{
		handshakeCh: make(chan quicPacket, 0),
		transportCh: make(chan quicPacket, 0),
		ctx:         context.Background(),
		cancel:      func() {},
	}

	select {
	case qt.handshakeCh <- quicPacket{data: []byte("hello"), ep: &endpoint{}}:
		t.Fatal("handshakeCh send should not succeed (unbuffered)")
	default:
	}

	select {
	case qt.transportCh <- quicPacket{data: []byte("world"), ep: &endpoint{}}:
		t.Fatal("transportCh send should not succeed (unbuffered)")
	default:
	}
}

func TestQUICTransportFallbackToUDP(t *testing.T) {
	enableQUICTransport(t)

	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })

	if conn.quicTransport == nil {
		t.Fatal("QUIC transport not created by NewConn")
	}
	qt := conn.quicTransport

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverConn.Close() })

	nodeKey, _ := addTestEndpoint(t, conn, serverConn)

	epIface, err := conn.ParseEndpoint(nodeKey.UntypedHexString())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	ep := epIface.(*endpoint)

	serverAddr := netip.MustParseAddrPort(serverConn.LocalAddr().String())
	ep.mu.Lock()
	ep.bestAddr.epAddr = epAddr{ap: serverAddr}
	ep.trustBestAddrUntil = mono.Now().Add(time.Hour)
	ep.mu.Unlock()

	qt.mu.Lock()
	s := &quicSession{done: make(chan struct{})}
	s.Close()
	if _, ok := qt.sessions[ep.publicKey]; !ok {
		qt.sessions[ep.publicKey] = s
	}
	qt.mu.Unlock()

	msg := make([]byte, 8+4)
	msg[8] = device.MessageTransportType
	msg[9] = 0x01
	msg[10] = 0x02
	msg[11] = 0x03
	err = conn.Send([][]byte{msg}, ep, 8)
	if err != nil {
		t.Fatalf("Conn.Send() error: %v", err)
	}

	buf := make([]byte, 1500)
	var found bool
	for i := 0; i < 50; i++ {
		serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := serverConn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n >= 1 && buf[0] == device.MessageTransportType {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("transport message not received within timeout")
	}
}

func TestQUICTransportSessionReconnection(t *testing.T) {
	enableQUICTransport(t)

	cServer := newConn(t.Logf)
	qtServer, err := newQUICTransport(cServer, 0)
	if err != nil {
		t.Fatalf("newQUICTransport server: %v", err)
	}
	t.Cleanup(qtServer.Close)

	serverQUICPort := qtServer.LocalPort()
	serverPub := key.NewNode().Public()

	cClient := newConn(t.Logf)
	qtClient, err := newQUICTransport(cClient, 0)
	if err != nil {
		t.Fatalf("newQUICTransport client: %v", err)
	}
	t.Cleanup(qtClient.Close)

	clientPort := uint16(qtClient.udpConn.LocalAddr().(*net.UDPAddr).Port)
	clientAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), clientPort)

	clientEP := &endpoint{
		c:         cServer,
		publicKey: serverPub,
	}

	pi := newPeerInfo(clientEP)
	epAddrVal := epAddr{ap: clientAddrPort}
	pi.epAddrs.Add(epAddrVal)

	cServer.mu.Lock()
	cServer.peerMap.byNodeKey[serverPub] = pi
	cServer.peerMap.byEpAddr[epAddrVal] = pi
	cServer.mu.Unlock()

	handshakeMsg := []byte{device.MessageInitiationType, 0x01, 0x02, 0x03}
	transportMsg := []byte{device.MessageTransportType, 0x04, 0x05, 0x06}

	serverWgPort := serverQUICPort - quicPortOffset
	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverWgPort)

	// Step 1: Establish session
	err = qtClient.sendToPeer(serverPub, serverAddr, [][]byte{handshakeMsg}, 0)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}

	select {
	case <-qtServer.handshakeCh:
	case <-time.After(time.Second):
		t.Fatal("timeout draining handshakeCh")
	}

	// Step 2: Close the session to force reconnection
	qtClient.mu.Lock()
	if s, ok := qtClient.sessions[serverPub]; ok {
		s.Close()
		delete(qtClient.sessions, serverPub)
	} else {
		qtClient.mu.Unlock()
		t.Fatal("no session to close")
	}
	qtClient.mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	// Step 3: Send again — should auto-reconnect
	err = qtClient.sendToPeer(serverPub, serverAddr, [][]byte{transportMsg}, 0)
	if err != nil {
		t.Fatalf("reconnect send: %v", err)
	}

	// Step 4: Verify message arrives at server
	var found bool
	for i := 0; i < 100; i++ {
		select {
		case pkt := <-qtServer.transportCh:
			if len(pkt.data) > 0 && pkt.data[0] == device.MessageTransportType {
				found = true
			}
		default:
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatal("transport message not received after reconnection")
	}
}

func TestQUICTransportRemovePeerSessions(t *testing.T) {
	enableQUICTransport(t)

	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport: %v", err)
	}
	t.Cleanup(qt.Close)

	keep := set.Set[key.NodePublic]{}
	removedPk := key.NewNode().Public()
	keptPk := key.NewNode().Public()
	keep.Add(keptPk)

	s1 := &quicSession{pubKey: removedPk, done: make(chan struct{})}
	s2 := &quicSession{pubKey: keptPk, done: make(chan struct{})}

	qt.mu.Lock()
	qt.sessions[removedPk] = s1
	qt.sessions[keptPk] = s2
	qt.mu.Unlock()

	qt.RemovePeerSessions(keep)

	qt.mu.Lock()
	_, hasRemoved := qt.sessions[removedPk]
	_, hasKept := qt.sessions[keptPk]
	qt.mu.Unlock()

	if hasRemoved {
		t.Fatal("session for removed peer should be deleted")
	}
	if !hasKept {
		t.Fatal("session for kept peer should still exist")
	}

	select {
	case <-s1.done:
	case <-time.After(time.Second):
		t.Fatal("removed session should be closed")
	}
}

func TestQUICTransportRemovePeerByKey(t *testing.T) {
	enableQUICTransport(t)

	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport: %v", err)
	}
	t.Cleanup(qt.Close)

	pk := key.NewNode().Public()
	s := &quicSession{pubKey: pk, done: make(chan struct{})}

	qt.mu.Lock()
	qt.sessions[pk] = s
	qt.mu.Unlock()

	qt.RemovePeerByKey(pk)

	qt.mu.Lock()
	_, exists := qt.sessions[pk]
	qt.mu.Unlock()

	if exists {
		t.Fatal("session should be deleted")
	}

	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("session should be closed")
	}
}

func TestQUICTransportRemovePeerSessionsNil(t *testing.T) {
	var qt *quicTransport
	qt.RemovePeerSessions(nil)
	qt.RemovePeerByKey(key.NodePublic{})
}

func TestQUICTransportRebind(t *testing.T) {
	enableQUICTransport(t)

	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport: %v", err)
	}
	t.Cleanup(qt.Close)

	origPort := qt.LocalPort()
	if origPort == 0 {
		t.Fatal("expected non-zero port")
	}

	// Add a session to verify it gets cleaned up
	pk := key.NewNode().Public()
	s := &quicSession{pubKey: pk, done: make(chan struct{})}
	qt.mu.Lock()
	qt.sessions[pk] = s
	qt.mu.Unlock()

	// Trigger rebind with current WG port (0 → OS-assigned)
	qt.Rebind(0)

	newPort := qt.LocalPort()
	if newPort == 0 {
		t.Fatal("expected non-zero port after rebind")
	}
	if newPort != origPort {
		t.Fatalf("port changed from %d to %d", origPort, newPort)
	}

	// Session should be closed
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("session should be closed after rebind")
	}

	// Session should be removed from map
	qt.mu.Lock()
	_, exists := qt.sessions[pk]
	qt.mu.Unlock()
	if exists {
		t.Fatal("session should be removed from map after rebind")
	}

	// Verify new listener works: establish a new session
	cServer := newConn(t.Logf)
	qtServer, err := newQUICTransport(cServer, 0)
	if err != nil {
		t.Fatalf("newQUICTransport server: %v", err)
	}
	t.Cleanup(qtServer.Close)

	serverQUICPort := qtServer.LocalPort()
	serverPub := key.NewNode().Public()

	clientAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), origPort)

	clientEP := &endpoint{
		c:         cServer,
		publicKey: serverPub,
	}

	pi := newPeerInfo(clientEP)
	epAddrVal := epAddr{ap: clientAddrPort}
	pi.epAddrs.Add(epAddrVal)

	cServer.mu.Lock()
	cServer.peerMap.byNodeKey[serverPub] = pi
	cServer.peerMap.byEpAddr[epAddrVal] = pi
	cServer.mu.Unlock()

	handshakeMsg := []byte{device.MessageInitiationType, 0x01, 0x02, 0x03}

	serverWgPort := serverQUICPort - quicPortOffset
	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverWgPort)

	err = qt.sendToPeer(serverPub, serverAddr, [][]byte{handshakeMsg}, 0)
	if err != nil {
		t.Fatalf("send after rebind: %v", err)
	}

	select {
	case <-qtServer.handshakeCh:
	case <-time.After(time.Second):
		t.Fatal("handshake not received after rebind")
	}
}

func TestQUICTransportDropCounters(t *testing.T) {
	enableQUICTransport(t)

	c := newConn(t.Logf)
	qt, err := newQUICTransport(c, 0)
	if err != nil {
		t.Fatalf("newQUICTransport: %v", err)
	}
	t.Cleanup(qt.Close)

	// Verify initial zero
	dth, dh := qt.Stats()
	if dth != 0 {
		t.Fatalf("initial droppedTransports = %d, want 0", dth)
	}
	if dh != 0 {
		t.Fatalf("initial droppedHandshakes = %d, want 0", dh)
	}

	// Simulate drops via Add and verify
	qt.droppedTransports.Add(3)
	qt.droppedHandshakes.Add(1)
	qt.logFirstDrop()

	dth, dh = qt.Stats()
	if dth != 3 {
		t.Fatalf("droppedTransports = %d, want 3", dth)
	}
	if dh != 1 {
		t.Fatalf("droppedHandshakes = %d, want 1", dh)
	}
}

func TestQUICTransportSentinelErrors(t *testing.T) {
	if errQUICSessionClosed == nil {
		t.Fatal("errQUICSessionClosed should be non-nil")
	}
	if errQUICNotEnabled == nil {
		t.Fatal("errQUICNotEnabled should be non-nil")
	}
}
