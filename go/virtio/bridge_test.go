package virtio

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBridgeSendAndReceive(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "virtio.sock")

	bridge := NewBridge(sock, BridgeOptions{MaxPendingBytes: 1024 * 1024})
	defer bridge.Close()

	rxCh := make(chan Envelope, 1)
	errCh := make(chan error, 1)
	bridge.SetHandlers(func(env Envelope) {
		rxCh <- env
	}, func(err error) {
		// Ignore errors caused by closing the socket.
		select {
		case errCh <- err:
		default:
		}
	})

	// Queue a message before the client connects.
	if err := bridge.Send(Envelope{V: 1, T: "ping", ID: 1, P: map[string]any{"x": uint64(1)}}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Client connects (QEMU would do this).
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Read queued ping.
	payload, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	env, err := DecodePayload(payload)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if env.T != "ping" || env.ID != 1 {
		t.Fatalf("unexpected env: %+v", env)
	}

	// Send a message from the client to the bridge.
	frame, err := EncodeFrame(Envelope{V: 1, T: "pong", ID: 2, P: map[string]any{"ok": true}})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-rxCh:
		if got.T != "pong" || got.ID != 2 {
			t.Fatalf("unexpected message: %+v", got)
		}
	case err := <-errCh:
		// Some platforms may surface EOF/errors on close; do not treat as success.
		_ = err
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for message")
	}

	// Ensure the socket file exists while running.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("expected socket file to exist: %v", err)
	}
}
