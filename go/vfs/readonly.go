package vfs

import "syscall"

// ReadonlyProvider wraps a provider and blocks write operations.
type ReadonlyProvider struct {
	backend VirtualProvider
}

func NewReadonlyProvider(backend VirtualProvider) *ReadonlyProvider {
	return &ReadonlyProvider{backend: backend}
}

func (p *ReadonlyProvider) Readonly() bool         { return true }
func (p *ReadonlyProvider) SupportsSymlinks() bool { return p.backend.SupportsSymlinks() }
func (p *ReadonlyProvider) SupportsWatch() bool    { return p.backend.SupportsWatch() }

func (p *ReadonlyProvider) Open(path string, flags string, mode uint32) (VirtualFileHandle, error) {
	if IsWriteFlag(flags) {
		return nil, CreateErrnoError(int(syscall.EROFS), "open", path)
	}
	return p.backend.Open(path, flags, mode)
}

func (p *ReadonlyProvider) Stat(path string) (Stats, error)       { return p.backend.Stat(path) }
func (p *ReadonlyProvider) Lstat(path string) (Stats, error)      { return p.backend.Lstat(path) }
func (p *ReadonlyProvider) ReadDir(path string) ([]Dirent, error) { return p.backend.ReadDir(path) }

func (p *ReadonlyProvider) Mkdir(path string, _ uint32) error {
	return CreateErrnoError(int(syscall.EROFS), "mkdir", path)
}
func (p *ReadonlyProvider) Rmdir(path string) error {
	return CreateErrnoError(int(syscall.EROFS), "rmdir", path)
}
func (p *ReadonlyProvider) Unlink(path string) error {
	return CreateErrnoError(int(syscall.EROFS), "unlink", path)
}
func (p *ReadonlyProvider) Rename(oldPath, _ string) error {
	return CreateErrnoError(int(syscall.EROFS), "rename", oldPath)
}

func (p *ReadonlyProvider) Readlink(path string) (string, error) { return p.backend.Readlink(path) }
func (p *ReadonlyProvider) Symlink(_ string, path string) error {
	return CreateErrnoError(int(syscall.EROFS), "symlink", path)
}
func (p *ReadonlyProvider) Realpath(path string) (string, error) { return p.backend.Realpath(path) }
func (p *ReadonlyProvider) Access(path string, mode uint32) error {
	return p.backend.Access(path, mode)
}
func (p *ReadonlyProvider) Truncate(path string, _ int64) error {
	return CreateErrnoError(int(syscall.EROFS), "truncate", path)
}
func (p *ReadonlyProvider) Close() error { return p.backend.Close() }
