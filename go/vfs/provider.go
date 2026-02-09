package vfs

import (
	"syscall"
)

// HookContext is passed to VFS hooks around provider/handle operations.
type HookContext struct {
	Op      string
	Path    string
	OldPath string
	NewPath string
	Flags   string
	Mode    uint32
	Offset  int64
	Length  int
	Size    int64
	Data    []byte
	Result  any
}

type Hooks struct {
	Before func(ctx *HookContext) error
	After  func(ctx *HookContext) error
}

// VirtualFileHandle is an opened file handle returned by a VirtualProvider.
type VirtualFileHandle interface {
	Path() string
	Flags() string
	Mode() uint32
	Position() int64
	SetPosition(pos int64)
	Closed() bool

	Read(buf []byte, offset, length int, position *int64) (int, error)
	Write(buf []byte, offset, length int, position *int64) (int, error)
	ReadFile() ([]byte, error)
	WriteFile(data []byte) error
	Stat() (Stats, error)
	Truncate(size int64) error
	Close() error
}

// VirtualProvider is the interface FsRpcService and MountRouterProvider operate on.
//
// Paths are absolute POSIX paths.
type VirtualProvider interface {
	Readonly() bool
	SupportsSymlinks() bool
	SupportsWatch() bool

	Open(path string, flags string, mode uint32) (VirtualFileHandle, error)
	Stat(path string) (Stats, error)
	Lstat(path string) (Stats, error)
	ReadDir(path string) ([]Dirent, error)
	Mkdir(path string, mode uint32) error
	Rmdir(path string) error
	Unlink(path string) error
	Rename(oldPath string, newPath string) error

	Readlink(path string) (string, error)
	Symlink(target string, path string) error
	Realpath(path string) (string, error)
	Access(path string, mode uint32) error
	Truncate(path string, size int64) error

	Close() error
}

// SandboxVfsProvider wraps a provider and runs hooks around each operation.
//
// It also wraps returned file handles to hook handle-level operations.
type SandboxVfsProvider struct {
	backend VirtualProvider
	hooks   Hooks
}

func NewSandboxVfsProvider(backend VirtualProvider, hooks Hooks) *SandboxVfsProvider {
	return &SandboxVfsProvider{backend: backend, hooks: hooks}
}

func (p *SandboxVfsProvider) Readonly() bool         { return p.backend.Readonly() }
func (p *SandboxVfsProvider) SupportsSymlinks() bool { return p.backend.SupportsSymlinks() }
func (p *SandboxVfsProvider) SupportsWatch() bool    { return p.backend.SupportsWatch() }

func (p *SandboxVfsProvider) Open(path string, flags string, mode uint32) (VirtualFileHandle, error) {
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "open", Path: path, Flags: flags, Mode: mode}); err != nil {
			return nil, err
		}
	}
	h, err := p.backend.Open(path, flags, mode)
	if err != nil {
		return nil, err
	}
	wrapped := p.wrapHandle(h, path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "open", Path: path, Flags: flags, Mode: mode, Result: wrapped})
	}
	return wrapped, nil
}

func (p *SandboxVfsProvider) Stat(path string) (Stats, error) {
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "stat", Path: path}); err != nil {
			return Stats{}, err
		}
	}
	st, err := p.backend.Stat(path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "stat", Path: path, Result: st})
	}
	return st, err
}

func (p *SandboxVfsProvider) Lstat(path string) (Stats, error) {
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "lstat", Path: path}); err != nil {
			return Stats{}, err
		}
	}
	st, err := p.backend.Lstat(path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "lstat", Path: path, Result: st})
	}
	return st, err
}

func (p *SandboxVfsProvider) ReadDir(path string) ([]Dirent, error) {
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "readdir", Path: path}); err != nil {
			return nil, err
		}
	}
	entries, err := p.backend.ReadDir(path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "readdir", Path: path, Result: entries})
	}
	return entries, err
}

func (p *SandboxVfsProvider) Mkdir(path string, mode uint32) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "mkdir", path)
	}
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "mkdir", Path: path, Mode: mode}); err != nil {
			return err
		}
	}
	err := p.backend.Mkdir(path, mode)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "mkdir", Path: path, Mode: mode})
	}
	return err
}

func (p *SandboxVfsProvider) Rmdir(path string) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "rmdir", path)
	}
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "rmdir", Path: path}); err != nil {
			return err
		}
	}
	err := p.backend.Rmdir(path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "rmdir", Path: path})
	}
	return err
}

func (p *SandboxVfsProvider) Unlink(path string) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "unlink", path)
	}
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "unlink", Path: path}); err != nil {
			return err
		}
	}
	err := p.backend.Unlink(path)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "unlink", Path: path})
	}
	return err
}

func (p *SandboxVfsProvider) Rename(oldPath, newPath string) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "rename", oldPath)
	}
	if p.hooks.Before != nil {
		if err := p.hooks.Before(&HookContext{Op: "rename", OldPath: oldPath, NewPath: newPath}); err != nil {
			return err
		}
	}
	err := p.backend.Rename(oldPath, newPath)
	if p.hooks.After != nil {
		_ = p.hooks.After(&HookContext{Op: "rename", OldPath: oldPath, NewPath: newPath})
	}
	return err
}

func (p *SandboxVfsProvider) Readlink(path string) (string, error) { return p.backend.Readlink(path) }
func (p *SandboxVfsProvider) Symlink(target, path string) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "symlink", path)
	}
	return p.backend.Symlink(target, path)
}
func (p *SandboxVfsProvider) Realpath(path string) (string, error) { return p.backend.Realpath(path) }
func (p *SandboxVfsProvider) Access(path string, mode uint32) error {
	return p.backend.Access(path, mode)
}
func (p *SandboxVfsProvider) Truncate(path string, size int64) error {
	if p.backend.Readonly() {
		return CreateErrnoError(int(syscall.EROFS), "truncate", path)
	}
	return p.backend.Truncate(path, size)
}
func (p *SandboxVfsProvider) Close() error { return p.backend.Close() }

func (p *SandboxVfsProvider) wrapHandle(h VirtualFileHandle, handlePath string) VirtualFileHandle {
	if p.hooks.Before == nil && p.hooks.After == nil {
		return h
	}
	return &hookedHandle{inner: h, hooks: p.hooks, handlePath: handlePath}
}

type hookedHandle struct {
	inner      VirtualFileHandle
	hooks      Hooks
	handlePath string
}

func (h *hookedHandle) Path() string {
	if p := h.inner.Path(); p != "" {
		return p
	}
	return h.handlePath
}
func (h *hookedHandle) Flags() string         { return h.inner.Flags() }
func (h *hookedHandle) Mode() uint32          { return h.inner.Mode() }
func (h *hookedHandle) Position() int64       { return h.inner.Position() }
func (h *hookedHandle) SetPosition(pos int64) { h.inner.SetPosition(pos) }
func (h *hookedHandle) Closed() bool          { return h.inner.Closed() }

func (h *hookedHandle) Read(buf []byte, offset, length int, position *int64) (int, error) {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "read", Path: h.Path(), Offset: deref(position), Length: length}); err != nil {
			return 0, err
		}
	}
	n, err := h.inner.Read(buf, offset, length, position)
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "read", Path: h.Path(), Offset: deref(position), Length: length, Result: n})
	}
	return n, err
}

func (h *hookedHandle) Write(buf []byte, offset, length int, position *int64) (int, error) {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "write", Path: h.Path(), Offset: deref(position), Length: length}); err != nil {
			return 0, err
		}
	}
	n, err := h.inner.Write(buf, offset, length, position)
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "write", Path: h.Path(), Offset: deref(position), Length: length, Result: n})
	}
	return n, err
}

func (h *hookedHandle) ReadFile() ([]byte, error) {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "readFile", Path: h.Path()}); err != nil {
			return nil, err
		}
	}
	data, err := h.inner.ReadFile()
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "readFile", Path: h.Path(), Result: data})
	}
	return data, err
}

func (h *hookedHandle) WriteFile(data []byte) error {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "writeFile", Path: h.Path(), Data: data}); err != nil {
			return err
		}
	}
	err := h.inner.WriteFile(data)
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "writeFile", Path: h.Path()})
	}
	return err
}

func (h *hookedHandle) Stat() (Stats, error) {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "stat", Path: h.Path()}); err != nil {
			return Stats{}, err
		}
	}
	st, err := h.inner.Stat()
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "stat", Path: h.Path(), Result: st})
	}
	return st, err
}

func (h *hookedHandle) Truncate(size int64) error {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "truncate", Path: h.Path(), Size: size}); err != nil {
			return err
		}
	}
	err := h.inner.Truncate(size)
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "truncate", Path: h.Path(), Size: size})
	}
	return err
}

func (h *hookedHandle) Close() error {
	if h.hooks.Before != nil {
		if err := h.hooks.Before(&HookContext{Op: "release", Path: h.Path()}); err != nil {
			return err
		}
	}
	err := h.inner.Close()
	if h.hooks.After != nil {
		_ = h.hooks.After(&HookContext{Op: "release", Path: h.Path()})
	}
	return err
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
