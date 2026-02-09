package vfs

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultEntryTTLms    = 1000
	DefaultAttrTTLms     = 1000
	DefaultNegativeTTLms = 250

	DT_REG = 1
	DT_DIR = 2
	DT_LNK = 10

	MAX_RPC_DATA = 60 * 1024
)

var linuxOpenFlags = struct {
	O_RDONLY uint32
	O_WRONLY uint32
	O_RDWR   uint32
	O_CREAT  uint32
	O_TRUNC  uint32
	O_APPEND uint32
}{
	O_RDONLY: 0,
	O_WRONLY: 1,
	O_RDWR:   2,
	O_CREAT:  0x40,
	O_TRUNC:  0x200,
	O_APPEND: 0x400,
}

type FsRequest struct {
	V  int
	T  string
	ID uint32
	P  struct {
		Op  string
		Req map[string]any
	}
}

type FsResponse struct {
	V  int
	T  string
	ID uint32
	P  struct {
		Op      string
		Err     int
		Res     map[string]any
		Message string
	}
}

type FsRpcMetrics struct {
	Requests     int
	Errors       int
	BytesRead    int
	BytesWritten int
	Ops          map[string]int
}

type FsRpcServiceOptions struct {
	Logger func(msg string)
}

type handleEntry struct {
	handle VirtualFileHandle
	ino    uint64
	path   string
	append bool
}

// FsRpcService implements the host-side FUSE RPC protocol used by sandboxfs.
type FsRpcService struct {
	provider VirtualProvider
	logger   func(msg string)

	nextIno    uint64
	nextHandle uint64

	pathToIno map[string]uint64
	inoToPath map[uint64]string
	handles   map[uint64]*handleEntry

	Metrics FsRpcMetrics
}

func NewFsRpcService(provider VirtualProvider, options FsRpcServiceOptions) *FsRpcService {
	s := &FsRpcService{
		provider:   provider,
		logger:     options.Logger,
		nextIno:    2,
		nextHandle: 1,
		pathToIno:  map[string]uint64{"/": 1},
		inoToPath:  map[uint64]string{1: "/"},
		handles:    map[uint64]*handleEntry{},
		Metrics:    FsRpcMetrics{Ops: map[string]int{}},
	}
	return s
}

func (s *FsRpcService) HandleRequest(msg FsRequest) FsResponse {
	start := time.Now()
	op := msg.P.Op
	errno := 0
	var res map[string]any
	message := ""

	out := FsResponse{V: 1, T: "fs_response", ID: msg.ID}
	out.P.Op = op

	result, err := s.dispatch(op, msg.P.Req)
	if err != nil {
		en, msgText := normalizeError(err)
		errno = en
		message = msgText
		if op == "lookup" && errno == int(syscall.ENOENT) {
			res = map[string]any{"entry_ttl_ms": DefaultNegativeTTLms}
		}
	} else {
		res = result
	}

	// metrics
	s.record(op, errno)
	if s.logger != nil {
		dur := time.Since(start).Milliseconds()
		extra := ""
		if op == "read" && res != nil {
			if b, ok := res["data"].([]byte); ok {
				extra = fmt.Sprintf(" bytes=%d", len(b))
			}
		}
		if op == "write" && res != nil {
			switch v := res["size"].(type) {
			case int:
				extra = fmt.Sprintf(" bytes=%d", v)
			case int64:
				extra = fmt.Sprintf(" bytes=%d", v)
			case uint64:
				extra = fmt.Sprintf(" bytes=%d", v)
			}
		}
		s.logger(fmt.Sprintf("op=%s err=%d dur=%dms%s", op, errno, dur, extra))
	}

	out.P.Err = errno
	if res != nil {
		out.P.Res = res
	}
	if message != "" && errno != 0 {
		out.P.Message = message
	}

	return out
}

func (s *FsRpcService) Close() error {
	// Close all open handles.
	entries := make([]*handleEntry, 0, len(s.handles))
	for _, e := range s.handles {
		entries = append(entries, e)
	}
	s.handles = map[uint64]*handleEntry{}
	for _, e := range entries {
		_ = e.handle.Close()
	}
	return nil
}

func (s *FsRpcService) dispatch(op string, req map[string]any) (map[string]any, error) {
	switch op {
	case "lookup":
		return s.handleLookup(req)
	case "getattr":
		return s.handleGetattr(req)
	case "readdir":
		return s.handleReaddir(req)
	case "open":
		return s.handleOpen(req)
	case "read":
		return s.handleRead(req)
	case "write":
		return s.handleWrite(req)
	case "create":
		return s.handleCreate(req)
	case "mkdir":
		return s.handleMkdir(req)
	case "unlink":
		return s.handleUnlink(req)
	case "rename":
		return s.handleRename(req)
	case "truncate":
		return s.handleTruncate(req)
	case "release":
		return s.handleRelease(req)
	default:
		return nil, CreateErrnoError(int(syscall.ENOSYS), op, "")
	}
}

func (s *FsRpcService) handleLookup(req map[string]any) (map[string]any, error) {
	parentIno, err := requireUint(req["parent_ino"], "lookup", "parent_ino")
	if err != nil {
		return nil, err
	}
	name, err := requireString(req["name"], "lookup", "name")
	if err != nil {
		return nil, err
	}
	if err := validateName(name, "lookup"); err != nil {
		return nil, err
	}
	parentPath, err := s.requirePath(uint64(parentIno), "lookup")
	if err != nil {
		return nil, err
	}
	entryPath := normalizePath(path.Join(parentPath, name))
	st, err := s.provider.Stat(entryPath)
	if err != nil {
		return nil, err
	}
	ino := s.ensureIno(entryPath)
	attr := statsToAttr(ino, st)
	return map[string]any{"entry": map[string]any{"ino": ino, "attr": attr, "attr_ttl_ms": DefaultAttrTTLms, "entry_ttl_ms": DefaultEntryTTLms}}, nil
}

func (s *FsRpcService) handleGetattr(req map[string]any) (map[string]any, error) {
	inoN, err := requireUint(req["ino"], "getattr", "ino")
	if err != nil {
		return nil, err
	}
	entryPath, err := s.requirePath(uint64(inoN), "getattr")
	if err != nil {
		return nil, err
	}
	st, err := s.provider.Stat(entryPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{"attr": statsToAttr(uint64(inoN), st), "attr_ttl_ms": DefaultAttrTTLms}, nil
}

func (s *FsRpcService) handleReaddir(req map[string]any) (map[string]any, error) {
	inoN, err := requireUint(req["ino"], "readdir", "ino")
	if err != nil {
		return nil, err
	}
	offsetN, err := requireUint(defaultAny(req["offset"], 0), "readdir", "offset")
	if err != nil {
		return nil, err
	}
	maxEntriesN, err := requireUint(defaultAny(req["max_entries"], 1024), "readdir", "max_entries")
	if err != nil {
		return nil, err
	}
	maxEntries := int(maxEntriesN)
	if maxEntries < 1 {
		maxEntries = 1
	}
	if maxEntries > 4096 {
		maxEntries = 4096
	}

	entryPath, err := s.requirePath(uint64(inoN), "readdir")
	if err != nil {
		return nil, err
	}

	entries, err := s.provider.ReadDir(entryPath)
	if err != nil {
		return nil, err
	}
	// stable ordering
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	start := int(offsetN)
	if start > len(entries) {
		start = len(entries)
	}

	respEntries := make([]map[string]any, 0)
	for idx := start; idx < len(entries) && len(respEntries) < maxEntries; idx++ {
		ent := entries[idx]
		name := ent.Name
		if name == "" || strings.Contains(name, "/") || strings.ContainsRune(name, '\x00') {
			continue
		}
		childPath := normalizePath(path.Join(entryPath, name))
		childIno := s.ensureIno(childPath)
		typeCode := DT_REG
		if ent.IsDirectory() {
			typeCode = DT_DIR
		} else if ent.IsSymbolicLink() {
			typeCode = DT_LNK
		}
		respEntries = append(respEntries, map[string]any{"ino": childIno, "name": name, "type": typeCode, "offset": idx + 1})
	}

	nextOffset := 0
	if start+len(respEntries) < len(entries) {
		nextOffset = start + len(respEntries)
	}

	return map[string]any{"entries": respEntries, "next_offset": nextOffset, "entry_ttl_ms": DefaultEntryTTLms}, nil
}

func (s *FsRpcService) handleOpen(req map[string]any) (map[string]any, error) {
	inoN, err := requireUint(req["ino"], "open", "ino")
	if err != nil {
		return nil, err
	}
	flagsN, err := requireUint(req["flags"], "open", "flags")
	if err != nil {
		return nil, err
	}
	entryPath, err := s.requirePath(uint64(inoN), "open")
	if err != nil {
		return nil, err
	}
	openFlags, truncate, appendMode, err := parseOpenFlagsForOpen(uint32(flagsN))
	if err != nil {
		return nil, err
	}
	h, err := s.provider.Open(entryPath, openFlags, 0)
	if err != nil {
		return nil, err
	}
	if truncate {
		_ = h.Truncate(0)
	}
	fh := s.allocateHandle(h, uint64(inoN), entryPath, appendMode)
	return map[string]any{"fh": fh, "open_flags": 0}, nil
}

func (s *FsRpcService) handleRead(req map[string]any) (map[string]any, error) {
	fhN, err := requireUint(req["fh"], "read", "fh")
	if err != nil {
		return nil, err
	}
	offsetN, err := requireUint(defaultAny(req["offset"], 0), "read", "offset")
	if err != nil {
		return nil, err
	}
	sizeN, err := requireUint(defaultAny(req["size"], 0), "read", "size")
	if err != nil {
		return nil, err
	}
	if sizeN > MAX_RPC_DATA {
		return nil, CreateErrnoError(int(syscall.EINVAL), "read", "")
	}
	entry, err := s.getHandle(uint64(fhN), "read")
	if err != nil {
		return nil, err
	}
	buf := make([]byte, int(sizeN))
	pos := int64(offsetN)
	n, err := entry.handle.Read(buf, 0, int(sizeN), &pos)
	if err != nil {
		return nil, err
	}
	data := buf[:n]
	s.Metrics.BytesRead += n
	return map[string]any{"data": append([]byte(nil), data...)}, nil
}

func (s *FsRpcService) handleWrite(req map[string]any) (map[string]any, error) {
	fhN, err := requireUint(req["fh"], "write", "fh")
	if err != nil {
		return nil, err
	}
	offsetN, err := requireUint(defaultAny(req["offset"], 0), "write", "offset")
	if err != nil {
		return nil, err
	}
	data, ok := req["data"].([]byte)
	if !ok {
		return nil, CreateErrnoError(int(syscall.EINVAL), "write", "")
	}
	if len(data) > MAX_RPC_DATA {
		return nil, CreateErrnoError(int(syscall.EINVAL), "write", "")
	}
	entry, err := s.getHandle(uint64(fhN), "write")
	if err != nil {
		return nil, err
	}
	var pos *int64
	if entry.append {
		pos = nil
	} else {
		p := int64(offsetN)
		pos = &p
	}
	n, err := entry.handle.Write(data, 0, len(data), pos)
	if err != nil {
		return nil, err
	}
	s.Metrics.BytesWritten += n
	return map[string]any{"size": n}, nil
}

func (s *FsRpcService) handleCreate(req map[string]any) (map[string]any, error) {
	parentIno, err := requireUint(req["parent_ino"], "create", "parent_ino")
	if err != nil {
		return nil, err
	}
	name, err := requireString(req["name"], "create", "name")
	if err != nil {
		return nil, err
	}
	modeN, err := requireUint(defaultAny(req["mode"], 0o644), "create", "mode")
	if err != nil {
		return nil, err
	}
	flagsN, err := requireUint(defaultAny(req["flags"], 0), "create", "flags")
	if err != nil {
		return nil, err
	}
	if err := validateName(name, "create"); err != nil {
		return nil, err
	}
	parentPath, err := s.requirePath(uint64(parentIno), "create")
	if err != nil {
		return nil, err
	}
	entryPath := normalizePath(path.Join(parentPath, name))
	appendMode := (uint32(flagsN) & linuxOpenFlags.O_APPEND) != 0
	h, err := s.provider.Open(entryPath, openFlagsToString(uint32(flagsN), true), uint32(modeN))
	if err != nil {
		return nil, err
	}
	st, err := h.Stat()
	if err != nil {
		return nil, err
	}
	ino := s.ensureIno(entryPath)
	fh := s.allocateHandle(h, ino, entryPath, appendMode)
	return map[string]any{
		"entry":      map[string]any{"ino": ino, "attr": statsToAttr(ino, st), "attr_ttl_ms": DefaultAttrTTLms, "entry_ttl_ms": DefaultEntryTTLms},
		"fh":         fh,
		"open_flags": 0,
	}, nil
}

func (s *FsRpcService) handleMkdir(req map[string]any) (map[string]any, error) {
	parentIno, err := requireUint(req["parent_ino"], "mkdir", "parent_ino")
	if err != nil {
		return nil, err
	}
	name, err := requireString(req["name"], "mkdir", "name")
	if err != nil {
		return nil, err
	}
	modeN, err := requireUint(defaultAny(req["mode"], 0o755), "mkdir", "mode")
	if err != nil {
		return nil, err
	}
	if err := validateName(name, "mkdir"); err != nil {
		return nil, err
	}
	parentPath, err := s.requirePath(uint64(parentIno), "mkdir")
	if err != nil {
		return nil, err
	}
	entryPath := normalizePath(path.Join(parentPath, name))
	if err := s.provider.Mkdir(entryPath, uint32(modeN)); err != nil {
		return nil, err
	}
	st, err := s.provider.Stat(entryPath)
	if err != nil {
		return nil, err
	}
	ino := s.ensureIno(entryPath)
	return map[string]any{"entry": map[string]any{"ino": ino, "attr": statsToAttr(ino, st), "attr_ttl_ms": DefaultAttrTTLms, "entry_ttl_ms": DefaultEntryTTLms}}, nil
}

func (s *FsRpcService) handleUnlink(req map[string]any) (map[string]any, error) {
	parentIno, err := requireUint(req["parent_ino"], "unlink", "parent_ino")
	if err != nil {
		return nil, err
	}
	name, err := requireString(req["name"], "unlink", "name")
	if err != nil {
		return nil, err
	}
	if err := validateName(name, "unlink"); err != nil {
		return nil, err
	}
	parentPath, err := s.requirePath(uint64(parentIno), "unlink")
	if err != nil {
		return nil, err
	}
	entryPath := normalizePath(path.Join(parentPath, name))
	if err := s.provider.Unlink(entryPath); err != nil {
		return nil, err
	}
	s.removeMapping(entryPath)
	return map[string]any{}, nil
}

func (s *FsRpcService) handleRename(req map[string]any) (map[string]any, error) {
	oldParent, err := requireUint(req["old_parent_ino"], "rename", "old_parent_ino")
	if err != nil {
		return nil, err
	}
	oldName, err := requireString(req["old_name"], "rename", "old_name")
	if err != nil {
		return nil, err
	}
	newParent, err := requireUint(req["new_parent_ino"], "rename", "new_parent_ino")
	if err != nil {
		return nil, err
	}
	newName, err := requireString(req["new_name"], "rename", "new_name")
	if err != nil {
		return nil, err
	}
	flagsN, err := requireUint(defaultAny(req["flags"], 0), "rename", "flags")
	if err != nil {
		return nil, err
	}
	if flagsN != 0 {
		return nil, CreateErrnoError(int(syscall.EINVAL), "rename", "")
	}
	if err := validateName(oldName, "rename"); err != nil {
		return nil, err
	}
	if err := validateName(newName, "rename"); err != nil {
		return nil, err
	}
	oldParentPath, err := s.requirePath(uint64(oldParent), "rename")
	if err != nil {
		return nil, err
	}
	newParentPath, err := s.requirePath(uint64(newParent), "rename")
	if err != nil {
		return nil, err
	}
	oldPath := normalizePath(path.Join(oldParentPath, oldName))
	newPath := normalizePath(path.Join(newParentPath, newName))
	if err := s.provider.Rename(oldPath, newPath); err != nil {
		return nil, err
	}
	s.renameMapping(oldPath, newPath)
	return map[string]any{}, nil
}

func (s *FsRpcService) handleTruncate(req map[string]any) (map[string]any, error) {
	inoN, err := requireUint(req["ino"], "truncate", "ino")
	if err != nil {
		return nil, err
	}
	sizeN, err := requireUint(defaultAny(req["size"], 0), "truncate", "size")
	if err != nil {
		return nil, err
	}
	entryPath, err := s.requirePath(uint64(inoN), "truncate")
	if err != nil {
		return nil, err
	}
	if err := s.provider.Truncate(entryPath, int64(sizeN)); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

func (s *FsRpcService) handleRelease(req map[string]any) (map[string]any, error) {
	fhN, err := requireUint(req["fh"], "release", "fh")
	if err != nil {
		return nil, err
	}
	entry := s.handles[uint64(fhN)]
	if entry == nil {
		return nil, CreateErrnoError(int(syscall.EBADF), "release", "")
	}
	delete(s.handles, uint64(fhN))
	_ = entry.handle.Close()
	return map[string]any{}, nil
}

// ---- helpers ----

func normalizePath(pth string) string {
	n := path.Clean(pth)
	if !strings.HasPrefix(n, "/") {
		n = "/" + n
	}
	if n != "/" && strings.HasSuffix(n, "/") {
		n = strings.TrimSuffix(n, "/")
	}
	return n
}

func validateName(name string, op string) error {
	if name == "" || strings.Contains(name, "/") || strings.ContainsRune(name, '\x00') {
		return CreateErrnoError(int(syscall.EINVAL), op, name)
	}
	return nil
}

func requireUint(value any, op, field string) (uint64, error) {
	switch v := value.(type) {
	case int:
		if v < 0 {
			return 0, CreateErrnoError(int(syscall.EINVAL), op, field)
		}
		return uint64(v), nil
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	case float64:
		if v < 0 || v != float64(uint64(v)) {
			return 0, CreateErrnoError(int(syscall.EINVAL), op, field)
		}
		return uint64(v), nil
	default:
		return 0, CreateErrnoError(int(syscall.EINVAL), op, field)
	}
}

func requireString(value any, op, field string) (string, error) {
	v, ok := value.(string)
	if !ok {
		return "", CreateErrnoError(int(syscall.EINVAL), op, field)
	}
	return v, nil
}

func defaultAny(v any, def any) any {
	if v == nil {
		return def
	}
	return v
}

func statsToAttr(ino uint64, st Stats) map[string]any {
	return map[string]any{
		"ino":      ino,
		"mode":     st.Mode,
		"nlink":    st.Nlink,
		"uid":      st.UID,
		"gid":      st.GID,
		"size":     st.Size,
		"atime_ms": st.AtimeMs,
		"mtime_ms": st.MtimeMs,
		"ctime_ms": st.CtimeMs,
	}
}

func openFlagsToString(flags uint32, forceCreate bool) string {
	access := flags & (linuxOpenFlags.O_RDONLY | linuxOpenFlags.O_WRONLY | linuxOpenFlags.O_RDWR)
	appendMode := (flags & linuxOpenFlags.O_APPEND) != 0
	trunc := (flags & linuxOpenFlags.O_TRUNC) != 0
	create := (flags&linuxOpenFlags.O_CREAT) != 0 || forceCreate

	if appendMode {
		if access == linuxOpenFlags.O_RDWR {
			return "a+"
		}
		return "a"
	}
	if create || trunc {
		if access == linuxOpenFlags.O_RDWR {
			return "w+"
		}
		return "w"
	}
	if access == linuxOpenFlags.O_RDWR {
		return "r+"
	}
	if access == linuxOpenFlags.O_WRONLY {
		return "r+"
	}
	return "r"
}

func parseOpenFlagsForOpen(flags uint32) (openFlags string, truncate bool, appendMode bool, err error) {
	if (flags & linuxOpenFlags.O_CREAT) != 0 {
		return "", false, false, CreateErrnoError(int(syscall.EINVAL), "open", "")
	}
	truncate = (flags & linuxOpenFlags.O_TRUNC) != 0
	access := flags & (linuxOpenFlags.O_RDONLY | linuxOpenFlags.O_WRONLY | linuxOpenFlags.O_RDWR)
	appendMode = (flags & linuxOpenFlags.O_APPEND) != 0

	appendEnabled := appendMode && access != linuxOpenFlags.O_RDONLY
	if appendEnabled {
		if access == linuxOpenFlags.O_RDWR {
			openFlags = "a+"
		} else {
			openFlags = "a"
		}
	} else {
		if access == linuxOpenFlags.O_RDWR || access == linuxOpenFlags.O_WRONLY {
			openFlags = "r+"
		} else {
			openFlags = "r"
		}
	}
	return openFlags, truncate, appendEnabled, nil
}

func (s *FsRpcService) ensureIno(entryPath string) uint64 {
	n := normalizePath(entryPath)
	if ino, ok := s.pathToIno[n]; ok {
		return ino
	}
	ino := s.nextIno
	s.nextIno++
	s.pathToIno[n] = ino
	s.inoToPath[ino] = n
	return ino
}

func (s *FsRpcService) requirePath(ino uint64, op string) (string, error) {
	p, ok := s.inoToPath[ino]
	if !ok {
		return "", CreateErrnoError(int(syscall.ENOENT), op, "")
	}
	return p, nil
}

func (s *FsRpcService) allocateHandle(h VirtualFileHandle, ino uint64, entryPath string, appendMode bool) uint64 {
	fh := s.nextHandle
	s.nextHandle++
	s.handles[fh] = &handleEntry{handle: h, ino: ino, path: entryPath, append: appendMode}
	return fh
}

func (s *FsRpcService) getHandle(fh uint64, op string) (*handleEntry, error) {
	e := s.handles[fh]
	if e == nil {
		return nil, CreateErrnoError(int(syscall.EBADF), op, "")
	}
	return e, nil
}

func (s *FsRpcService) removeMapping(entryPath string) {
	n := normalizePath(entryPath)
	for pth, ino := range s.pathToIno {
		if pth == n || strings.HasPrefix(pth, n+"/") {
			delete(s.pathToIno, pth)
			delete(s.inoToPath, ino)
		}
	}
}

func (s *FsRpcService) renameMapping(oldPath string, newPath string) {
	oldN := normalizePath(oldPath)
	newN := normalizePath(newPath)
	updates := make([]struct {
		old, new string
		ino      uint64
	}, 0)
	for pth, ino := range s.pathToIno {
		if pth == oldN || strings.HasPrefix(pth, oldN+"/") {
			suffix := strings.TrimPrefix(pth, oldN)
			updates = append(updates, struct {
				old, new string
				ino      uint64
			}{old: pth, new: newN + suffix, ino: ino})
		}
	}
	for _, u := range updates {
		delete(s.pathToIno, u.old)
		s.pathToIno[u.new] = u.ino
		s.inoToPath[u.ino] = u.new
	}
	for _, h := range s.handles {
		if h.path == oldN || strings.HasPrefix(h.path, oldN+"/") {
			suffix := strings.TrimPrefix(h.path, oldN)
			h.path = newN + suffix
		}
	}
}

func (s *FsRpcService) record(op string, errno int) {
	s.Metrics.Requests++
	s.Metrics.Ops[op] = s.Metrics.Ops[op] + 1
	if errno != 0 {
		s.Metrics.Errors++
	}
}

type errnoResult struct {
	errno   int
	message string
}

func normalizeError(err error) (int, string) {
	var ee *ErrnoError
	if errors.As(err, &ee) {
		en := ee.Errno
		if en < 0 {
			en = -en
		}
		msg := ee.Message
		if msg == "" {
			msg = ee.Error()
		}
		return en, msg
	}
	// Default mapping
	return int(syscall.EIO), err.Error()
}
