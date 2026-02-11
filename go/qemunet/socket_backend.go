package qemunet

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	gonetstack "github.com/earendil-works/gondolin-go/netstack"
)

// SocketBackend wires QemuNetworkBackend policy logic to a unix-socket QEMU net stream.
//
// It is the Go equivalent of host/src/qemu-net.ts start()/attachSocket/resetStack plumbing.
//
// All mutable runtime state is owned by the event-loop goroutine.
type SocketBackend struct {
	core *QemuNetworkBackend

	mu       sync.Mutex
	listener net.Listener
	started  bool
	closed   bool

	eventCh chan func()
	closeCh chan struct{}
	doneCh  chan struct{}

	// event-loop-owned state
	conn     net.Conn
	connGen  uint64
	stack    *gonetstack.NetworkStack
	tcpByKey map[string]*socketTcpSession
}

type socketTcpSession struct {
	key      string
	srcIP    string
	srcPort  uint16
	dstIP    string
	dstPort  uint16
	protocol string // "http" | "tls"
	ingress  TcpIngressSession
	tls      *socketTlsSession
}

type socketTlsSession struct {
	guestConn  net.Conn
	serverConn net.Conn
	tlsConn    *tls.Conn
	closeOnce  sync.Once
}

func (s *socketTlsSession) close() {
	s.closeOnce.Do(func() {
		_ = s.tlsConn.Close()
		_ = s.serverConn.Close()
		_ = s.guestConn.Close()
	})
}

type socketStackUdpResponderFunc func(msg any)

func (f socketStackUdpResponderFunc) HandleUdpResponse(msg any) { f(msg) }

type socketStackTcpErrorFunc func(key string)

func (f socketStackTcpErrorFunc) HandleTcpError(key string) { f(key) }

func NewSocketBackend(options QemuNetworkOptions) (*SocketBackend, error) {
	core, err := NewQemuNetworkBackend(options)
	if err != nil {
		return nil, err
	}

	b := &SocketBackend{
		core:     core,
		tcpByKey: map[string]*socketTcpSession{},
	}

	core.stackUdp = socketStackUdpResponderFunc(func(msg any) {
		b.post(func() {
			b.handleUdpResponseFromCore(msg)
		})
	})

	core.stackTcp = socketStackTcpErrorFunc(func(key string) {
		b.post(func() {
			if b.stack == nil {
				return
			}
			b.stack.HandleTcpError(key)
			b.flushToQemu()
		})
	})

	return b, nil
}

func (b *SocketBackend) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return errors.New("socket backend closed")
	}
	if b.started {
		return nil
	}

	socketPath := b.core.options.SocketPath
	if socketPath == "" {
		return errors.New("socket path is required")
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	b.listener = ln
	b.eventCh = make(chan func(), 1024)
	b.closeCh = make(chan struct{})
	b.doneCh = make(chan struct{})
	b.started = true

	go b.eventLoop()
	go b.acceptLoop(ln)

	return nil
}

func (b *SocketBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	ln := b.listener
	b.listener = nil
	closeCh := b.closeCh
	doneCh := b.doneCh
	socketPath := b.core.options.SocketPath
	b.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if closeCh != nil {
		close(closeCh)
	}
	if doneCh != nil {
		<-doneCh
	}
	if socketPath != "" {
		_ = os.Remove(socketPath)
	}
	return nil
}

func (b *SocketBackend) Core() *QemuNetworkBackend { return b.core }

func (b *SocketBackend) post(fn func()) {
	b.mu.Lock()
	if b.closed || b.eventCh == nil || b.closeCh == nil {
		b.mu.Unlock()
		return
	}
	eventCh := b.eventCh
	closeCh := b.closeCh
	b.mu.Unlock()

	select {
	case eventCh <- fn:
	case <-closeCh:
	}
}

func (b *SocketBackend) eventLoop() {
	defer close(b.doneCh)

	for {
		select {
		case fn := <-b.eventCh:
			if fn != nil {
				fn()
			}
		case <-b.closeCh:
			b.cleanupRuntime()
			return
		}
	}
}

func (b *SocketBackend) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}

		b.post(func() {
			b.attachConn(conn)
		})
	}
}

func (b *SocketBackend) attachConn(conn net.Conn) {
	if b.conn != nil {
		_ = b.conn.Close()
	}
	b.conn = conn
	b.connGen++
	gen := b.connGen

	b.resetRuntime()

	go b.readLoop(conn, gen)
}

func (b *SocketBackend) readLoop(conn net.Conn, gen uint64) {
	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			b.post(func() {
				if b.conn != conn || b.connGen != gen || b.stack == nil {
					return
				}
				b.stack.WriteToNetwork(chunk)
				b.flushToQemu()
			})
		}
		if err != nil {
			b.post(func() {
				if b.conn == conn && b.connGen == gen {
					b.detachConn()
				}
			})
			return
		}
	}
}

func (b *SocketBackend) detachConn() {
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	b.cleanupRuntimeStateOnly()
}

func (b *SocketBackend) cleanupRuntime() {
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	b.cleanupRuntimeStateOnly()
}

func (b *SocketBackend) cleanupRuntimeStateOnly() {
	for _, sess := range b.tcpByKey {
		if sess.tls != nil {
			sess.tls.close()
		}
	}
	b.tcpByKey = map[string]*socketTcpSession{}

	for _, sess := range b.core.udpSessions {
		sess.Socket.Close()
	}
	b.core.udpSessions = map[string]*udpSession{}

	if b.stack != nil {
		b.stack.Reset()
		b.stack = nil
	}
}

func (b *SocketBackend) resetRuntime() {
	b.cleanupRuntimeStateOnly()

	stack := gonetstack.NewNetworkStack(gonetstack.NetworkStackOptions{
		GatewayIP:       b.core.options.GatewayIP,
		VmIP:            b.core.options.VmIP,
		GatewayMac:      b.core.options.GatewayMac,
		VmMac:           b.core.options.VmMac,
		TxQueueMaxBytes: b.core.options.TxQueueMaxBytes,
		Callbacks: gonetstack.NetworkCallbacks{
			OnUdpSend: func(message gonetstack.UdpSendMessage) {
				b.handleUdpSend(message)
			},
			OnTcpConnect: func(message gonetstack.TcpConnectMessage) {
				b.handleTcpConnect(message)
			},
			OnTcpSend: func(message gonetstack.TcpSendMessage) {
				b.handleTcpSend(message)
			},
			OnTcpClose: func(message gonetstack.TcpCloseMessage) {
				b.handleTcpClose(message)
			},
			OnTcpPause: func(_ gonetstack.TcpPauseMessage) {
				// No upstream socket to pause (HTTP/TLS interception only)
			},
			OnTcpResume: func(_ gonetstack.TcpResumeMessage) {
				// No upstream socket to resume (HTTP/TLS interception only)
			},
		},
		AllowTcpFlow: func(info gonetstack.TcpFlowInfo) bool {
			sess := b.tcpByKey[info.Key]
			if sess == nil {
				return false
			}
			if info.Protocol != gonetstack.TcpFlowHTTP && info.Protocol != gonetstack.TcpFlowTLS {
				return false
			}
			sess.protocol = string(info.Protocol)
			return true
		},
	})

	b.stack = stack
	b.tcpByKey = map[string]*socketTcpSession{}
}

func (b *SocketBackend) flushToQemu() {
	if b.conn == nil || b.stack == nil {
		return
	}

	for b.stack.HasPendingData() {
		chunk := b.stack.ReadFromNetwork(64 * 1024)
		if len(chunk) == 0 {
			return
		}

		_ = b.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		written := 0
		for written < len(chunk) {
			n, err := b.conn.Write(chunk[written:])
			if err != nil {
				b.detachConn()
				return
			}
			if n <= 0 {
				b.detachConn()
				return
			}
			written += n
		}
	}
}

func (b *SocketBackend) handleUdpSend(message gonetstack.UdpSendMessage) {
	b.core.HandleUdpSend(UdpSendMessage{
		Key:     message.Key,
		SrcIP:   message.SrcIP,
		SrcPort: message.SrcPort,
		DstIP:   message.DstIP,
		DstPort: message.DstPort,
		Payload: message.Payload,
	})
}

func (b *SocketBackend) handleUdpResponseFromCore(msg any) {
	if b.stack == nil {
		return
	}
	m, ok := msg.(map[string]any)
	if !ok {
		return
	}

	data, _ := m["data"].([]byte)
	srcIP, _ := m["srcIP"].(string)
	dstIP, _ := m["dstIP"].(string)
	srcPort := uint16(anyToUint64(m["srcPort"]))
	dstPort := uint16(anyToUint64(m["dstPort"]))

	b.stack.HandleUdpResponse(struct {
		Data    []byte
		SrcIP   string
		SrcPort uint16
		DstIP   string
		DstPort uint16
	}{
		Data:    append([]byte(nil), data...),
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
	})
	b.flushToQemu()
}

func (b *SocketBackend) handleTcpConnect(message gonetstack.TcpConnectMessage) {
	b.tcpByKey[message.Key] = &socketTcpSession{
		key:     message.Key,
		srcIP:   message.SrcIP,
		srcPort: message.SrcPort,
		dstIP:   message.DstIP,
		dstPort: message.DstPort,
	}

	if b.stack != nil {
		b.stack.HandleTcpConnected(message.Key)
		b.flushToQemu()
	}
}

func (b *SocketBackend) handleTcpSend(message gonetstack.TcpSendMessage) {
	sess := b.tcpByKey[message.Key]
	if sess == nil {
		return
	}

	switch sess.protocol {
	case string(gonetstack.TcpFlowHTTP):
		b.handlePlainHttpData(message.Key, sess, message.Data)
	case string(gonetstack.TcpFlowTLS):
		b.handleTlsData(message.Key, sess, message.Data)
	default:
		// Shouldn't happen because netstack only emits OnTcpSend once flow is classified,
		// but keep behavior defensive.
	}
}

func (b *SocketBackend) handlePlainHttpData(key string, sess *socketTcpSession, data []byte) {
	if b.stack == nil {
		return
	}

	_ = b.core.handleHttpDataWithWriter(key, &sess.ingress, data, httpWriter{
		scheme: "http",
		write: func(chunk []byte) {
			if b.stack == nil {
				return
			}
			b.stack.HandleTcpData(key, append([]byte(nil), chunk...))
		},
		finish: func() {
			if b.stack == nil {
				return
			}
			b.stack.HandleTcpEnd(key)
		},
	})

	b.flushToQemu()
}

func (b *SocketBackend) handleTlsData(key string, sess *socketTcpSession, data []byte) {
	if b.stack == nil {
		return
	}

	if err := b.ensureTlsSession(key, sess); err != nil {
		b.stack.HandleTcpError(key)
		delete(b.tcpByKey, key)
		b.flushToQemu()
		return
	}

	if sess.tls == nil {
		b.stack.HandleTcpError(key)
		delete(b.tcpByKey, key)
		b.flushToQemu()
		return
	}

	_, err := sess.tls.guestConn.Write(data)
	if err != nil {
		b.stack.HandleTcpError(key)
		if sess.tls != nil {
			sess.tls.close()
		}
		delete(b.tcpByKey, key)
		b.flushToQemu()
	}
}

func (b *SocketBackend) ensureTlsSession(key string, sess *socketTcpSession) error {
	if sess.tls != nil {
		return nil
	}

	guestConn, serverConn := net.Pipe()
	cfg := &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = sess.dstIP
			}
			tlsCfg, err := b.core.getTlsContextAsync(name)
			if err != nil {
				return nil, err
			}
			if len(tlsCfg.Certificates) == 0 {
				return nil, errors.New("tls context has no certificates")
			}
			return &tlsCfg.Certificates[0], nil
		},
	}

	tlsConn := tls.Server(serverConn, cfg)
	tlsSess := &socketTlsSession{
		guestConn:  guestConn,
		serverConn: serverConn,
		tlsConn:    tlsConn,
	}
	sess.tls = tlsSess

	go b.tlsEncryptedLoop(key, sess, tlsSess)
	go b.tlsPlainLoop(key, sess, tlsSess)
	return nil
}

func (b *SocketBackend) tlsEncryptedLoop(key string, sess *socketTcpSession, tlsSess *socketTlsSession) {
	buf := make([]byte, 32*1024)
	for {
		n, err := tlsSess.guestConn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			b.post(func() {
				current := b.tcpByKey[key]
				if current != sess || current == nil || current.tls != tlsSess || b.stack == nil {
					return
				}
				b.stack.HandleTcpData(key, chunk)
				b.flushToQemu()
			})
		}
		if err != nil {
			b.post(func() {
				current := b.tcpByKey[key]
				if current == sess && current != nil && current.tls == tlsSess {
					if b.stack != nil {
						b.stack.HandleTcpClosed(key)
						b.flushToQemu()
					}
					delete(b.tcpByKey, key)
				}
				tlsSess.close()
			})
			return
		}
	}
}

func (b *SocketBackend) tlsPlainLoop(key string, sess *socketTcpSession, tlsSess *socketTlsSession) {
	buf := make([]byte, 32*1024)
	for {
		n, err := tlsSess.tlsConn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			b.post(func() {
				current := b.tcpByKey[key]
				if current != sess || current == nil || current.tls != tlsSess || b.stack == nil {
					return
				}
				_ = b.core.handleHttpDataWithWriter(key, &current.ingress, chunk, httpWriter{
					scheme: "https",
					write: func(clear []byte) {
						if current.tls == nil {
							return
						}
						_, _ = current.tls.tlsConn.Write(clear)
					},
					finish: func() {
						if current.tls != nil {
							_ = current.tls.tlsConn.Close()
						}
						if b.stack != nil {
							b.stack.HandleTcpEnd(key)
						}
					},
				})
				b.flushToQemu()
			})
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			b.post(func() {
				current := b.tcpByKey[key]
				if current == sess && current != nil && current.tls == tlsSess {
					if b.stack != nil {
						b.stack.HandleTcpError(key)
						b.flushToQemu()
					}
					delete(b.tcpByKey, key)
				}
				tlsSess.close()
			})
			return
		}
	}
}

func (b *SocketBackend) handleTcpClose(message gonetstack.TcpCloseMessage) {
	sess := b.tcpByKey[message.Key]
	if sess == nil {
		return
	}
	if sess.tls != nil {
		sess.tls.close()
		sess.tls = nil
	}
	delete(b.tcpByKey, message.Key)
}

func anyToUint64(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint8:
		return uint64(x)
	case int:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case float64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	default:
		return 0
	}
}
