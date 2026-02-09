package vfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// RealFSProvider proxies operations to the host filesystem under a root directory.
type RealFSProvider struct {
	rootPath string
}

func NewRealFSProvider(root string) (*RealFSProvider, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the dir doesn't exist yet, still use abs.
		real = abs
	}
	return &RealFSProvider{rootPath: real}, nil
}

func (p *RealFSProvider) RootPath() string { return p.rootPath }

func (p *RealFSProvider) Readonly() bool         { return false }
func (p *RealFSProvider) SupportsSymlinks() bool { return true }
func (p *RealFSProvider) SupportsWatch() bool    { return false }

func (p *RealFSProvider) resolveHostPath(entryPath string) (string, error) {
	n := entryPath
	if !strings.HasPrefix(n, "/") {
		n = "/" + n
	}
	if strings.ContainsRune(n, '\x00') {
		return "", CreateErrnoError(int(syscall.EINVAL), "resolve", entryPath)
	}

	// Resolve the virtual absolute path against the host root by prefixing with "." so
	// an absolute entry path can't escape the root, while still detecting attempts to
	// traverse above the root (e.g. "/../outside").
	host := filepath.Join(p.rootPath, filepath.FromSlash("."+n))
	host = filepath.Clean(host)

	relCheck, err := filepath.Rel(p.rootPath, host)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", CreateErrnoError(int(syscall.ENOENT), "resolve", entryPath)
	}
	return host, nil
}

func (p *RealFSProvider) Open(entryPath string, flags string, mode uint32) (VirtualFileHandle, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return nil, err
	}
	osFlags, err := parseOpenFlags(flags)
	if err != nil {
		return nil, err
	}
	perm := os.FileMode(mode & 0o777)
	if perm == 0 {
		perm = 0o644
	}
	f, err := os.OpenFile(host, osFlags, perm)
	if err != nil {
		return nil, mapOsError("open", entryPath, err)
	}
	return &realHandle{file: f, path: NormalizeVfsPath(entryPath), flags: flags, mode: fileModeToStatMode(perm), pos: 0, append: flags == "a" || flags == "a+"}, nil
}

func (p *RealFSProvider) Stat(entryPath string) (Stats, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return Stats{}, err
	}
	st, err := os.Stat(host)
	if err != nil {
		return Stats{}, mapOsError("stat", entryPath, err)
	}
	return osInfoToStats(st), nil
}

func (p *RealFSProvider) Lstat(entryPath string) (Stats, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return Stats{}, err
	}
	st, err := os.Lstat(host)
	if err != nil {
		return Stats{}, mapOsError("lstat", entryPath, err)
	}
	return osInfoToStats(st), nil
}

func (p *RealFSProvider) ReadDir(entryPath string) ([]Dirent, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(host)
	if err != nil {
		return nil, mapOsError("readdir", entryPath, err)
	}
	out := make([]Dirent, 0, len(entries))
	for _, e := range entries {
		t := DirentFile
		if e.IsDir() {
			t = DirentDir
		} else {
			if e.Type()&os.ModeSymlink != 0 {
				t = DirentSymlink
			}
		}
		out = append(out, Dirent{Name: e.Name(), Type: t})
	}
	return out, nil
}

func (p *RealFSProvider) Mkdir(entryPath string, mode uint32) error {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return err
	}
	perm := os.FileMode(mode & 0o777)
	if perm == 0 {
		perm = 0o755
	}
	if err := os.Mkdir(host, perm); err != nil {
		return mapOsError("mkdir", entryPath, err)
	}
	return nil
}

func (p *RealFSProvider) Rmdir(entryPath string) error {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return err
	}
	if err := os.Remove(host); err != nil {
		return mapOsError("rmdir", entryPath, err)
	}
	return nil
}

func (p *RealFSProvider) Unlink(entryPath string) error {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return err
	}
	if err := os.Remove(host); err != nil {
		return mapOsError("unlink", entryPath, err)
	}
	return nil
}

func (p *RealFSProvider) Rename(oldPath string, newPath string) error {
	from, err := p.resolveHostPath(oldPath)
	if err != nil {
		return err
	}
	to, err := p.resolveHostPath(newPath)
	if err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil {
		return mapOsError("rename", oldPath, err)
	}
	return nil
}

func (p *RealFSProvider) Readlink(entryPath string) (string, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return "", err
	}
	target, err := os.Readlink(host)
	if err != nil {
		return "", mapOsError("readlink", entryPath, err)
	}
	// Return the link target as stored.
	return target, nil
}

func (p *RealFSProvider) Symlink(target string, entryPath string) error {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return err
	}
	if err := os.Symlink(target, host); err != nil {
		return mapOsError("symlink", entryPath, err)
	}
	return nil
}

func (p *RealFSProvider) Realpath(entryPath string) (string, error) {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(host)
	if err != nil {
		return "", mapOsError("realpath", entryPath, err)
	}
	rel, err := filepath.Rel(p.rootPath, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", CreateErrnoError(int(syscall.ENOENT), "realpath", entryPath)
	}
	if rel == "." {
		return "/", nil
	}
	return "/" + filepath.ToSlash(rel), nil
}

func (p *RealFSProvider) Access(entryPath string, _ uint32) error {
	// Only existence check for now.
	_, err := p.Stat(entryPath)
	return err
}

func (p *RealFSProvider) Truncate(entryPath string, size int64) error {
	host, err := p.resolveHostPath(entryPath)
	if err != nil {
		return err
	}
	if err := os.Truncate(host, size); err != nil {
		return mapOsError("truncate", entryPath, err)
	}
	return nil
}

func (p *RealFSProvider) Close() error { return nil }

func parseOpenFlags(flags string) (int, error) {
	switch flags {
	case "r":
		return os.O_RDONLY, nil
	case "r+":
		return os.O_RDWR, nil
	case "w":
		return os.O_WRONLY | os.O_CREATE | os.O_TRUNC, nil
	case "w+":
		return os.O_RDWR | os.O_CREATE | os.O_TRUNC, nil
	case "a":
		return os.O_WRONLY | os.O_CREATE | os.O_APPEND, nil
	case "a+":
		return os.O_RDWR | os.O_CREATE | os.O_APPEND, nil
	default:
		return 0, CreateErrnoError(int(syscall.EINVAL), "open", flags)
	}
}

func mapOsError(op string, entryPath string, err error) error {
	// Preserve errno if possible.
	var pe *os.PathError
	if errors.As(err, &pe) {
		if errno, ok := pe.Err.(syscall.Errno); ok {
			return &ErrnoError{Errno: int(errno), Syscall: op, Path: entryPath, Message: pe.Err.Error()}
		}
	}
	return &ErrnoError{Errno: int(syscall.EIO), Syscall: op, Path: entryPath, Message: err.Error()}
}

func osInfoToStats(info os.FileInfo) Stats {
	mode := fileModeToStatMode(info.Mode())
	sz := info.Size()
	mt := info.ModTime().UnixMilli()
	return Stats{Mode: mode, Nlink: 1, UID: 0, GID: 0, Size: sz, AtimeMs: mt, MtimeMs: mt, CtimeMs: mt}
}

type realHandle struct {
	file   *os.File
	path   string
	flags  string
	mode   uint32
	pos    int64
	closed bool
	append bool
}

func (h *realHandle) Path() string          { return h.path }
func (h *realHandle) Flags() string         { return h.flags }
func (h *realHandle) Mode() uint32          { return h.mode }
func (h *realHandle) Position() int64       { return h.pos }
func (h *realHandle) SetPosition(pos int64) { h.pos = pos }
func (h *realHandle) Closed() bool          { return h.closed }

func (h *realHandle) Read(buf []byte, offset, length int, position *int64) (int, error) {
	if h.closed {
		return 0, CreateErrnoError(int(syscall.EBADF), "read", h.path)
	}
	p := h.pos
	if position != nil {
		p = *position
	}
	n, err := h.file.ReadAt(buf[offset:offset+length], p)
	if position == nil {
		h.pos = p + int64(n)
	}
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, nil
}

func (h *realHandle) Write(buf []byte, offset, length int, position *int64) (int, error) {
	if h.closed {
		return 0, CreateErrnoError(int(syscall.EBADF), "write", h.path)
	}
	data := buf[offset : offset+length]
	p := h.pos
	if h.append {
		st, _ := h.file.Stat()
		p = st.Size()
	} else if position != nil {
		p = *position
	}
	n, err := h.file.WriteAt(data, p)
	if position == nil {
		h.pos = p + int64(n)
	}
	return n, err
}

func (h *realHandle) ReadFile() ([]byte, error) {
	if h.closed {
		return nil, CreateErrnoError(int(syscall.EBADF), "readFile", h.path)
	}
	// Read from disk by reopening the file path.
	return os.ReadFile(h.file.Name())
}

func (h *realHandle) WriteFile(data []byte) error {
	if err := h.Truncate(0); err != nil {
		return err
	}
	_, err := h.Write(data, 0, len(data), ptrInt64(0))
	return err
}

func (h *realHandle) Stat() (Stats, error) {
	if h.closed {
		return Stats{}, CreateErrnoError(int(syscall.EBADF), "stat", h.path)
	}
	st, err := h.file.Stat()
	if err != nil {
		return Stats{}, err
	}
	return osInfoToStats(st), nil
}

func (h *realHandle) Truncate(size int64) error {
	if h.closed {
		return CreateErrnoError(int(syscall.EBADF), "truncate", h.path)
	}
	return h.file.Truncate(size)
}

func (h *realHandle) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	return h.file.Close()
}
