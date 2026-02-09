package vfs

import (
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
)

type memKind int

const (
	memFile memKind = iota
	memDir
	memSymlink
)

type memEntry struct {
	kind    memKind
	mode    uint32
	data    []byte
	target  string
	atimeMs int64
	mtimeMs int64
	ctimeMs int64
}

// MemoryProvider is an in-memory VFS provider.
type MemoryProvider struct {
	mu       sync.Mutex
	entries  map[string]*memEntry
	readonly bool
}

func NewMemoryProvider() *MemoryProvider {
	now := nowMs()
	p := &MemoryProvider{entries: map[string]*memEntry{}}
	p.entries["/"] = &memEntry{kind: memDir, mode: S_IFDIR | 0o755, atimeMs: now, mtimeMs: now, ctimeMs: now}
	return p
}

func (p *MemoryProvider) SetReadOnly() { p.mu.Lock(); p.readonly = true; p.mu.Unlock() }

func (p *MemoryProvider) Readonly() bool         { p.mu.Lock(); defer p.mu.Unlock(); return p.readonly }
func (p *MemoryProvider) SupportsSymlinks() bool { return true }
func (p *MemoryProvider) SupportsWatch() bool    { return false }

func (p *MemoryProvider) Open(entryPath string, flags string, mode uint32) (VirtualFileHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly && IsWriteFlag(flags) {
		return nil, CreateErrnoError(int(syscall.EROFS), "open", entryPath)
	}

	n := NormalizeVfsPath(entryPath)
	create := flags == "w" || flags == "w+" || flags == "a" || flags == "a+"
	truncate := flags == "w" || flags == "w+"
	appendMode := flags == "a" || flags == "a+"

	e, ok := p.entries[n]
	if !ok {
		if !create {
			return nil, CreateErrnoError(int(syscall.ENOENT), "open", entryPath)
		}
		// ensure parent exists
		parent := path.Dir(n)
		if parent == "." {
			parent = "/"
		}
		pe, ok := p.entries[parent]
		if !ok || pe.kind != memDir {
			return nil, CreateErrnoError(int(syscall.ENOENT), "open", entryPath)
		}
		now := nowMs()
		perm := mode
		if perm == 0 {
			perm = 0o644
		}
		e = &memEntry{kind: memFile, mode: S_IFREG | (perm & 0o777), data: []byte{}, atimeMs: now, mtimeMs: now, ctimeMs: now}
		p.entries[n] = e
	}
	if e.kind == memDir {
		return nil, CreateErrnoError(int(syscall.EISDIR), "open", entryPath)
	}

	if truncate {
		e.data = []byte{}
		now := nowMs()
		e.mtimeMs = now
		e.ctimeMs = now
	}

	h := &memoryHandle{provider: p, path: n, flags: flags, mode: e.mode, pos: 0, closed: false, append: appendMode}
	if appendMode {
		h.pos = int64(len(e.data))
	}
	return h, nil
}

func (p *MemoryProvider) Stat(entryPath string) (Stats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return Stats{}, CreateErrnoError(int(syscall.ENOENT), "stat", entryPath)
	}
	// Follow symlink
	if e.kind == memSymlink {
		target := NormalizeVfsPath(e.target)
		if te, ok := p.entries[target]; ok {
			e = te
		} else {
			return Stats{}, CreateErrnoError(int(syscall.ENOENT), "stat", entryPath)
		}
	}
	return entryToStats(e), nil
}

func (p *MemoryProvider) Lstat(entryPath string) (Stats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return Stats{}, CreateErrnoError(int(syscall.ENOENT), "lstat", entryPath)
	}
	return entryToStats(e), nil
}

func (p *MemoryProvider) ReadDir(entryPath string) ([]Dirent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return nil, CreateErrnoError(int(syscall.ENOENT), "readdir", entryPath)
	}
	if e.kind != memDir {
		return nil, CreateErrnoError(int(syscall.ENOTDIR), "readdir", entryPath)
	}

	prefix := n
	if prefix != "/" {
		prefix += "/"
	}

	childSet := map[string]struct{}{}
	for pth := range p.entries {
		if pth == n {
			continue
		}
		if !strings.HasPrefix(pth, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(pth, prefix)
		seg := strings.SplitN(remainder, "/", 2)[0]
		if seg != "" {
			childSet[seg] = struct{}{}
		}
	}

	children := make([]string, 0, len(childSet))
	for c := range childSet {
		children = append(children, c)
	}
	sort.Strings(children)

	out := make([]Dirent, 0, len(children))
	for _, name := range children {
		childPath := n
		if childPath == "/" {
			childPath = "/" + name
		} else {
			childPath = childPath + "/" + name
		}
		ce := p.entries[childPath]
		dt := DirentFile
		if ce != nil {
			switch ce.kind {
			case memDir:
				dt = DirentDir
			case memSymlink:
				dt = DirentSymlink
			default:
				dt = DirentFile
			}
		}
		out = append(out, Dirent{Name: name, Type: dt})
	}
	return out, nil
}

func (p *MemoryProvider) Mkdir(entryPath string, mode uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly {
		return CreateErrnoError(int(syscall.EROFS), "mkdir", entryPath)
	}
	n := NormalizeVfsPath(entryPath)
	if n == "/" {
		return nil
	}
	if _, ok := p.entries[n]; ok {
		return nil
	}
	parent := path.Dir(n)
	if parent == "." {
		parent = "/"
	}
	pe, ok := p.entries[parent]
	if !ok || pe.kind != memDir {
		return CreateErrnoError(int(syscall.ENOENT), "mkdir", entryPath)
	}
	now := nowMs()
	perm := mode
	if perm == 0 {
		perm = 0o755
	}
	p.entries[n] = &memEntry{kind: memDir, mode: S_IFDIR | (perm & 0o777), atimeMs: now, mtimeMs: now, ctimeMs: now}
	return nil
}

func (p *MemoryProvider) Rmdir(entryPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly {
		return CreateErrnoError(int(syscall.EROFS), "rmdir", entryPath)
	}
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return CreateErrnoError(int(syscall.ENOENT), "rmdir", entryPath)
	}
	if e.kind != memDir {
		return CreateErrnoError(int(syscall.ENOTDIR), "rmdir", entryPath)
	}
	prefix := n
	if prefix != "/" {
		prefix += "/"
	}
	for pth := range p.entries {
		if strings.HasPrefix(pth, prefix) {
			return CreateErrnoError(int(syscall.ENOTEMPTY), "rmdir", entryPath)
		}
	}
	delete(p.entries, n)
	return nil
}

func (p *MemoryProvider) Unlink(entryPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly {
		return CreateErrnoError(int(syscall.EROFS), "unlink", entryPath)
	}
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return CreateErrnoError(int(syscall.ENOENT), "unlink", entryPath)
	}
	if e.kind == memDir {
		return CreateErrnoError(int(syscall.EISDIR), "unlink", entryPath)
	}
	delete(p.entries, n)
	return nil
}

func (p *MemoryProvider) Rename(oldPath string, newPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly {
		return CreateErrnoError(int(syscall.EROFS), "rename", oldPath)
	}
	from := NormalizeVfsPath(oldPath)
	to := NormalizeVfsPath(newPath)
	if _, ok := p.entries[from]; !ok {
		return CreateErrnoError(int(syscall.ENOENT), "rename", oldPath)
	}
	updates := make([]struct{ old, new string }, 0)
	for pth := range p.entries {
		if pth == from || strings.HasPrefix(pth, from+"/") {
			suffix := strings.TrimPrefix(pth, from)
			updates = append(updates, struct{ old, new string }{old: pth, new: to + suffix})
		}
	}
	for _, u := range updates {
		p.entries[u.new] = p.entries[u.old]
		delete(p.entries, u.old)
	}
	return nil
}

func (p *MemoryProvider) Readlink(entryPath string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := NormalizeVfsPath(entryPath)
	e, ok := p.entries[n]
	if !ok {
		return "", CreateErrnoError(int(syscall.ENOENT), "readlink", entryPath)
	}
	if e.kind != memSymlink {
		return "", CreateErrnoError(int(syscall.EINVAL), "readlink", entryPath)
	}
	return e.target, nil
}

func (p *MemoryProvider) Symlink(target string, entryPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readonly {
		return CreateErrnoError(int(syscall.EROFS), "symlink", entryPath)
	}
	n := NormalizeVfsPath(entryPath)
	parent := path.Dir(n)
	if parent == "." {
		parent = "/"
	}
	pe, ok := p.entries[parent]
	if !ok || pe.kind != memDir {
		return CreateErrnoError(int(syscall.ENOENT), "symlink", entryPath)
	}
	now := nowMs()
	p.entries[n] = &memEntry{kind: memSymlink, mode: S_IFLNK | 0o777, target: target, atimeMs: now, mtimeMs: now, ctimeMs: now}
	return nil
}

func (p *MemoryProvider) Realpath(entryPath string) (string, error) {
	// For memory provider we just normalize
	return NormalizeVfsPath(entryPath), nil
}

func (p *MemoryProvider) Access(entryPath string, _ uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := NormalizeVfsPath(entryPath)
	if _, ok := p.entries[n]; !ok {
		return CreateErrnoError(int(syscall.ENOENT), "access", entryPath)
	}
	return nil
}

func (p *MemoryProvider) Truncate(entryPath string, size int64) error {
	h, err := p.Open(entryPath, "r+", 0)
	if err != nil {
		return err
	}
	defer h.Close()
	return h.Truncate(size)
}

func (p *MemoryProvider) Close() error { return nil }

func entryToStats(e *memEntry) Stats {
	sz := int64(0)
	if e.kind == memFile {
		sz = int64(len(e.data))
	}
	return Stats{Mode: e.mode, Nlink: 1, UID: 0, GID: 0, Size: sz, AtimeMs: e.atimeMs, MtimeMs: e.mtimeMs, CtimeMs: e.ctimeMs}
}

type memoryHandle struct {
	provider *MemoryProvider
	path     string
	flags    string
	mode     uint32
	pos      int64
	closed   bool
	append   bool
}

func (h *memoryHandle) Path() string          { return h.path }
func (h *memoryHandle) Flags() string         { return h.flags }
func (h *memoryHandle) Mode() uint32          { return h.mode }
func (h *memoryHandle) Position() int64       { return h.pos }
func (h *memoryHandle) SetPosition(pos int64) { h.pos = pos }
func (h *memoryHandle) Closed() bool          { return h.closed }

func (h *memoryHandle) ensureOpen(op string) error {
	if h.closed {
		return CreateErrnoError(int(syscall.EBADF), op, h.path)
	}
	return nil
}

func (h *memoryHandle) Read(buf []byte, offset, length int, position *int64) (int, error) {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if err := h.ensureOpen("read"); err != nil {
		return 0, err
	}
	e := h.provider.entries[h.path]
	if e == nil || e.kind != memFile {
		return 0, CreateErrnoError(int(syscall.ENOENT), "read", h.path)
	}

	pos := h.pos
	if position != nil {
		pos = *position
	}
	if pos < 0 {
		pos = 0
	}
	if pos >= int64(len(e.data)) {
		return 0, nil
	}
	avail := int64(len(e.data)) - pos
	n := int64(length)
	if n > avail {
		n = avail
	}
	copy(buf[offset:offset+int(n)], e.data[pos:pos+n])
	if position == nil {
		h.pos = pos + n
	}
	e.atimeMs = nowMs()
	return int(n), nil
}

func (h *memoryHandle) Write(buf []byte, offset, length int, position *int64) (int, error) {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if err := h.ensureOpen("write"); err != nil {
		return 0, err
	}
	if h.provider.readonly {
		return 0, CreateErrnoError(int(syscall.EROFS), "write", h.path)
	}
	e := h.provider.entries[h.path]
	if e == nil || e.kind != memFile {
		return 0, CreateErrnoError(int(syscall.ENOENT), "write", h.path)
	}

	writeData := buf[offset : offset+length]
	pos := h.pos
	if h.append {
		pos = int64(len(e.data))
	} else if position != nil {
		pos = *position
	}
	if pos < 0 {
		pos = 0
	}

	end := pos + int64(len(writeData))
	if end > int64(len(e.data)) {
		newData := make([]byte, end)
		copy(newData, e.data)
		e.data = newData
	}
	copy(e.data[pos:end], writeData)

	if position == nil {
		h.pos = end
	}
	now := nowMs()
	e.mtimeMs = now
	e.ctimeMs = now
	return len(writeData), nil
}

func (h *memoryHandle) ReadFile() ([]byte, error) {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if err := h.ensureOpen("readFile"); err != nil {
		return nil, err
	}
	e := h.provider.entries[h.path]
	if e == nil || e.kind != memFile {
		return nil, CreateErrnoError(int(syscall.ENOENT), "readFile", h.path)
	}
	e.atimeMs = nowMs()
	out := make([]byte, len(e.data))
	copy(out, e.data)
	return out, nil
}

func (h *memoryHandle) WriteFile(data []byte) error {
	if err := h.Truncate(0); err != nil {
		return err
	}
	_, err := h.Write(data, 0, len(data), ptrInt64(0))
	return err
}

func (h *memoryHandle) Stat() (Stats, error) {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if err := h.ensureOpen("stat"); err != nil {
		return Stats{}, err
	}
	e := h.provider.entries[h.path]
	if e == nil {
		return Stats{}, CreateErrnoError(int(syscall.ENOENT), "stat", h.path)
	}
	return entryToStats(e), nil
}

func (h *memoryHandle) Truncate(size int64) error {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if err := h.ensureOpen("truncate"); err != nil {
		return err
	}
	if h.provider.readonly {
		return CreateErrnoError(int(syscall.EROFS), "truncate", h.path)
	}
	e := h.provider.entries[h.path]
	if e == nil || e.kind != memFile {
		return CreateErrnoError(int(syscall.ENOENT), "truncate", h.path)
	}
	if size < 0 {
		size = 0
	}
	if size < int64(len(e.data)) {
		e.data = e.data[:size]
	} else if size > int64(len(e.data)) {
		newData := make([]byte, size)
		copy(newData, e.data)
		e.data = newData
	}
	now := nowMs()
	e.mtimeMs = now
	e.ctimeMs = now
	if h.pos > size {
		h.pos = size
	}
	return nil
}

func (h *memoryHandle) Close() error {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return nil
}

func ptrInt64(v int64) *int64 { return &v }
