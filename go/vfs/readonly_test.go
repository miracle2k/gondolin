package vfs

import (
	"errors"
	"syscall"
	"testing"
)

func isErrno(err error, errno syscall.Errno) bool {
	var ee *ErrnoError
	if errors.As(err, &ee) {
		return ee.Errno == int(errno)
	}
	return false
}

func TestReadonlyProviderBlocksWriteOperations(t *testing.T) {
	inner := NewMemoryProvider()
	h, err := inner.Open("/existing.txt", "w+", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := h.WriteFile([]byte("initial content")); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	_ = h.Close()
	if err := inner.Mkdir("/subdir", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	provider := NewReadonlyProvider(inner)
	if provider.Readonly() != true {
		t.Fatalf("expected readonly=true")
	}

	// Read operations should work
	rh, err := provider.Open("/existing.txt", "r", 0)
	if err != nil {
		t.Fatalf("open r: %v", err)
	}
	data, err := rh.ReadFile()
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	_ = rh.Close()
	if string(data) != "initial content" {
		t.Fatalf("unexpected content: %q", string(data))
	}

	st, err := provider.Stat("/existing.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st.IsFile() {
		t.Fatalf("expected file")
	}

	entries, err := provider.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "existing.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected existing.txt in entries")
	}

	// Write operations should be blocked
	cases := []struct {
		name string
		fn   func() error
	}{
		{"open new w", func() error { _, err := provider.Open("/new.txt", "w", 0); return err }},
		{"open existing w", func() error { _, err := provider.Open("/existing.txt", "w", 0); return err }},
		{"open existing a", func() error { _, err := provider.Open("/existing.txt", "a", 0); return err }},
		{"open existing r+", func() error { _, err := provider.Open("/existing.txt", "r+", 0); return err }},
		{"mkdir", func() error { return provider.Mkdir("/newdir", 0o755) }},
		{"unlink", func() error { return provider.Unlink("/existing.txt") }},
		{"rmdir", func() error { return provider.Rmdir("/subdir") }},
		{"rename", func() error { return provider.Rename("/existing.txt", "/renamed.txt") }},
	}

	for _, c := range cases {
		if err := c.fn(); err == nil || !isErrno(err, syscall.EROFS) {
			t.Fatalf("%s: expected EROFS, got %v", c.name, err)
		}
	}
}
