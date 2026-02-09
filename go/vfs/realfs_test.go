package vfs

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func makeTempDir(t *testing.T, prefix string) string {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func TestRealFSProviderProxiesFilesystemOperations(t *testing.T) {
	root := makeTempDir(t, "gondolin-vfs-")
	provider, err := NewRealFSProvider(root)
	if err != nil {
		t.Fatalf("NewRealFSProvider: %v", err)
	}

	if provider.Readonly() {
		t.Fatalf("expected readonly=false")
	}
	if !provider.SupportsSymlinks() {
		t.Fatalf("expected supportsSymlinks=true")
	}
	if provider.SupportsWatch() {
		t.Fatalf("expected supportsWatch=false")
	}

	abs, _ := filepath.Abs(root)
	real, _ := filepath.EvalSymlinks(abs)
	if provider.RootPath() != real {
		t.Fatalf("expected rootPath=%q, got %q", real, provider.RootPath())
	}

	if err := provider.Mkdir("/dir", 0o755); err != nil {
		t.Fatalf("mkdir /dir: %v", err)
	}
	if err := provider.Mkdir("/dir/sub", 0o755); err != nil {
		t.Fatalf("mkdir /dir/sub: %v", err)
	}

	entries, err := provider.ReadDir("/dir")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	foundSub := false
	for _, e := range entries {
		if e.Name == "sub" {
			foundSub = true
			break
		}
	}
	if !foundSub {
		t.Fatalf("expected sub in /dir")
	}

	// open + write + stat
	{
		fh, err := provider.Open("/dir/hello.txt", "w+", 0o644)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := fh.WriteFile([]byte("hello")); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
		st, err := fh.Stat()
		if err != nil {
			t.Fatalf("fh.stat: %v", err)
		}
		if !st.IsFile() {
			t.Fatalf("expected file")
		}
		_ = fh.Close()
	}

	st, err := provider.Stat("/dir/hello.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st.IsFile() {
		t.Fatalf("expected file")
	}

	if err := provider.Rename("/dir/hello.txt", "/dir/renamed.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := provider.Access("/dir/renamed.txt", 0); err != nil {
		t.Fatalf("access: %v", err)
	}

	// truncate via file handle
	{
		fh, err := provider.Open("/dir/renamed.txt", "r+", 0)
		if err != nil {
			t.Fatalf("open r+: %v", err)
		}
		if err := fh.Truncate(2); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		_ = fh.Close()

		check, err := provider.Open("/dir/renamed.txt", "r", 0)
		if err != nil {
			t.Fatalf("open r: %v", err)
		}
		contents, err := check.ReadFile()
		if err != nil {
			t.Fatalf("readFile: %v", err)
		}
		_ = check.Close()
		if string(contents) != "he" {
			t.Fatalf("expected he, got %q", string(contents))
		}
	}

	if err := provider.Unlink("/dir/renamed.txt"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := provider.Rmdir("/dir/sub"); err != nil {
		t.Fatalf("rmdir sub: %v", err)
	}
	if err := provider.Rmdir("/dir"); err != nil {
		t.Fatalf("rmdir dir: %v", err)
	}
	if _, err := provider.Stat("/dir"); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT after rmdir, got %v", err)
	}
}

func TestRealFSProviderBlocksPathTraversalOutsideRoot(t *testing.T) {
	root := makeTempDir(t, "gondolin-vfs-")
	provider, err := NewRealFSProvider(root)
	if err != nil {
		t.Fatalf("NewRealFSProvider: %v", err)
	}

	outsidePath := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(outsidePath)
	})

	if _, err := provider.Open("/../outside.txt", "r", 0); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
	if _, err := provider.Stat("/../outside.txt"); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
	if _, err := provider.ReadDir("/../"); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
	if _, err := provider.Open("/a/b/../../../../outside.txt", "r", 0); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
}

func TestRealFSProviderSymlinkReadlinkLstatRealpath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics require elevated permissions on Windows")
	}

	root := makeTempDir(t, "gondolin-vfs-")
	provider, err := NewRealFSProvider(root)
	if err != nil {
		t.Fatalf("NewRealFSProvider: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if err := provider.Symlink("target.txt", "/link.txt"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	linkTarget, err := provider.Readlink("/link.txt")
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if linkTarget != "target.txt" {
		t.Fatalf("expected target.txt, got %q", linkTarget)
	}

	lst, err := provider.Lstat("/link.txt")
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !lst.IsSymbolicLink() {
		t.Fatalf("expected symbolic link")
	}

	st, err := provider.Stat("/link.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st.IsFile() {
		t.Fatalf("expected file")
	}

	resolved, err := provider.Realpath("/link.txt")
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	if resolved != "/target.txt" {
		t.Fatalf("expected /target.txt, got %q", resolved)
	}
}
