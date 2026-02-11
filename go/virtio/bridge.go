package virtio

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Bridge listens on a unix socket path and exchanges framed CBOR messages.
//
// It is used as the host-side endpoint for QEMU -chardev socket,...,server=off.
// QEMU connects as a client to this unix socket.
//
// Bridge is safe for concurrent Send calls.
type Bridge struct {
	socketPath      string
	maxPendingBytes int

	mu           sync.Mutex
	listener     net.Listener
	conn         net.Conn
	pending      [][]byte
	pendingBytes int
	closed       bool

	onMessage func(env Envelope)
	onError   func(err error)
}

// BridgeOptions configures a Bridge.
type BridgeOptions struct {
	/** max queued outbound bytes before Send starts failing */
	MaxPendingBytes int
}

// NewBridge creates a bridge but does not start listening.
func NewBridge(socketPath string, opts BridgeOptions) *Bridge {
	maxPending := opts.MaxPendingBytes
	if maxPending <= 0 {
		maxPending = 8 * 1024 * 1024
	}
	return &Bridge{socketPath: socketPath, maxPendingBytes: maxPending}
}

// SocketPath returns the unix socket path the bridge listens on.
func (b *Bridge) SocketPath() string { return b.socketPath }

// SetHandlers sets message and error handlers.
//
// Handlers are invoked from the reader goroutine.
func (b *Bridge) SetHandlers(onMessage func(env Envelope), onError func(err error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onMessage = onMessage
	b.onError = onError
}

// Start begins listening on the bridge socket path.
func (b *Bridge) Start() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("bridge closed")
	}
	if b.listener != nil {
		b.mu.Unlock()
		return nil
	}
	socketPath := b.socketPath
	b.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = ln.Close()
		return errors.New("bridge closed")
	}
	b.listener = ln
	b.mu.Unlock()

	go b.acceptLoop(ln)
	return nil
}

func (b *Bridge) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			b.emitError(fmt.Errorf("accept: %w", err))
			return
		}
		b.attachConn(conn)
	}
}

func (b *Bridge) attachConn(conn net.Conn) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = conn.Close()
		return
	}
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	b.conn = conn
	pending := b.pending
	b.pending = nil
	b.pendingBytes = 0
	b.mu.Unlock()

	// Flush queued frames first.
	for _, frame := range pending {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(frame); err != nil {
			b.emitError(fmt.Errorf("write queued: %w", err))
			_ = conn.Close()
			b.detachConn(conn)
			return
		}
	}

	go b.readLoop(conn)
}

func (b *Bridge) detachConn(conn net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == conn {
		b.conn = nil
	}
}

func (b *Bridge) readLoop(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		b.detachConn(conn)
	}()

	for {
		payload, err := ReadFrame(conn)
		if err != nil {
			// EOF / closed is normal during shutdown.
			b.emitError(err)
			return
		}

		env, err := DecodePayload(payload)
		if err != nil {
			b.emitError(err)
			return
		}

		b.mu.Lock()
		onMessage := b.onMessage
		b.mu.Unlock()
		if onMessage != nil {
			onMessage(env)
		}
	}
}

func (b *Bridge) emitError(err error) {
	b.mu.Lock()
	onError := b.onError
	b.mu.Unlock()
	if onError != nil {
		onError(err)
	}
}

// Send sends an envelope over the bridge.
//
// If the QEMU side is not connected yet, the frame is queued until a connection
// arrives (bounded by MaxPendingBytes).
func (b *Bridge) Send(msg Envelope) error {
	frame, err := EncodeFrame(msg)
	if err != nil {
		return err
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("bridge closed")
	}
	conn := b.conn
	if conn == nil {
		if b.pendingBytes+len(frame) > b.maxPendingBytes {
			b.mu.Unlock()
			return errors.New("virtio bridge queue exceeded")
		}
		b.pending = append(b.pending, frame)
		b.pendingBytes += len(frame)
		b.mu.Unlock()
		return b.Start()
	}
	b.mu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(frame)
	if err != nil {
		b.emitError(err)
		_ = conn.Close()
		b.detachConn(conn)
	}
	return err
}

// Close shuts down the bridge and removes the unix socket file.
func (b *Bridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	ln := b.listener
	b.listener = nil
	conn := b.conn
	b.conn = nil
	socketPath := b.socketPath
	b.pending = nil
	b.pendingBytes = 0
	b.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
	_ = os.Remove(socketPath)
	return nil
}
