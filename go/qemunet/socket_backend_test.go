package qemunet

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketBackendStartAndClose(t *testing.T) {
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("qemu-net-%d.sock", time.Now().UnixNano()))
	defer os.Remove(sock)

	backend, err := NewSocketBackend(QemuNetworkOptions{SocketPath: sock})
	if err != nil {
		t.Fatalf("NewSocketBackend: %v", err)
	}

	if err := backend.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("expected socket file to exist: %v", err)
	}

	// Connect once to exercise accept/attach path.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = conn.Write([]byte{0, 0, 0, 0}) // empty qemu frame
	_ = conn.Close()

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
