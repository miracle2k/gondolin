package vfs

import (
	"errors"
	"reflect"
	"syscall"
	"testing"
)

var linuxTestOpenFlags = struct {
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

func createService() *FsRpcService {
	return NewFsRpcService(NewMemoryProvider(), FsRpcServiceOptions{})
}

func send(service *FsRpcService, op string, req map[string]any, id uint32) FsResponse {
	msg := FsRequest{V: 1, T: "fs_request", ID: id}
	msg.P.Op = op
	msg.P.Req = req
	return service.HandleRequest(msg)
}

func getResMap(t *testing.T, resp FsResponse) map[string]any {
	if resp.P.Res == nil {
		t.Fatalf("expected res, got nil (err=%d msg=%q)", resp.P.Err, resp.P.Message)
	}
	return resp.P.Res
}

func TestFsRpcCreateWriteRead(t *testing.T) {
	service := createService()
	defer service.Close()

	create := send(service, "create", map[string]any{"parent_ino": 1, "name": "hello.txt", "mode": 0o644, "flags": 0}, 1)
	if create.P.Err != 0 {
		t.Fatalf("create err=%d msg=%q", create.P.Err, create.P.Message)
	}
	fh := getResMap(t, create)["fh"].(uint64)

	write := send(service, "write", map[string]any{"fh": fh, "offset": 0, "data": []byte("hello")}, 2)
	if write.P.Err != 0 {
		t.Fatalf("write err=%d msg=%q", write.P.Err, write.P.Message)
	}
	if getResMap(t, write)["size"].(int) != 5 {
		t.Fatalf("expected size=5")
	}

	read := send(service, "read", map[string]any{"fh": fh, "offset": 0, "size": 5}, 3)
	if read.P.Err != 0 {
		t.Fatalf("read err=%d msg=%q", read.P.Err, read.P.Message)
	}
	data := getResMap(t, read)["data"].([]byte)
	if string(data) != "hello" {
		t.Fatalf("expected hello, got %q", string(data))
	}

	lookup := send(service, "lookup", map[string]any{"parent_ino": 1, "name": "hello.txt"}, 4)
	if lookup.P.Err != 0 {
		t.Fatalf("lookup err=%d msg=%q", lookup.P.Err, lookup.P.Message)
	}
	ino := getResMap(t, lookup)["entry"].(map[string]any)["ino"].(uint64)

	getattr := send(service, "getattr", map[string]any{"ino": ino}, 5)
	if getattr.P.Err != 0 {
		t.Fatalf("getattr err=%d msg=%q", getattr.P.Err, getattr.P.Message)
	}

	release := send(service, "release", map[string]any{"fh": fh}, 6)
	if release.P.Err != 0 {
		t.Fatalf("release err=%d msg=%q", release.P.Err, release.P.Message)
	}
}

func TestFsRpcReaddirOffsets(t *testing.T) {
	service := createService()
	defer service.Close()

	_ = send(service, "create", map[string]any{"parent_ino": 1, "name": "a.txt", "mode": 0o644, "flags": 0}, 1)
	_ = send(service, "create", map[string]any{"parent_ino": 1, "name": "b.txt", "mode": 0o644, "flags": 0}, 2)

	first := send(service, "readdir", map[string]any{"ino": 1, "offset": 0, "max_entries": 1}, 3)
	if first.P.Err != 0 {
		t.Fatalf("readdir first err=%d", first.P.Err)
	}
	firstEntries := getResMap(t, first)["entries"].([]map[string]any)
	if len(firstEntries) != 1 {
		t.Fatalf("expected 1 entry")
	}
	nextOffset := firstEntries[0]["offset"].(int)

	second := send(service, "readdir", map[string]any{"ino": 1, "offset": nextOffset, "max_entries": 1}, 4)
	if second.P.Err != 0 {
		t.Fatalf("readdir second err=%d", second.P.Err)
	}
	secondEntries := getResMap(t, second)["entries"].([]map[string]any)
	if len(secondEntries) != 1 {
		t.Fatalf("expected 1 entry")
	}
	if secondEntries[0]["name"].(string) == firstEntries[0]["name"].(string) {
		t.Fatalf("expected different entry")
	}
}

func TestFsRpcValidatesNamesAndPayloadSize(t *testing.T) {
	service := createService()
	defer service.Close()

	invalidName := send(service, "mkdir", map[string]any{"parent_ino": 1, "name": "bad/name", "mode": 0o755}, 1)
	if invalidName.P.Err != int(syscall.EINVAL) {
		t.Fatalf("expected EINVAL, got %d", invalidName.P.Err)
	}

	create := send(service, "create", map[string]any{"parent_ino": 1, "name": "big.txt", "mode": 0o644, "flags": 0}, 2)
	fh := getResMap(t, create)["fh"].(uint64)

	over := send(service, "write", map[string]any{"fh": fh, "offset": 0, "data": make([]byte, MAX_RPC_DATA+1)}, 3)
	if over.P.Err != int(syscall.EINVAL) {
		t.Fatalf("expected EINVAL, got %d", over.P.Err)
	}

	overRead := send(service, "read", map[string]any{"fh": fh, "offset": 0, "size": MAX_RPC_DATA + 1}, 4)
	if overRead.P.Err != int(syscall.EINVAL) {
		t.Fatalf("expected EINVAL, got %d", overRead.P.Err)
	}

	_ = send(service, "release", map[string]any{"fh": fh}, 5)
}

func TestFsRpcUnlinkRemovesMappingsAndLookupReturnsNegativeTTL(t *testing.T) {
	service := createService()
	defer service.Close()

	_ = send(service, "create", map[string]any{"parent_ino": 1, "name": "hello.txt", "mode": 0o644, "flags": 0}, 1)

	lookup1 := send(service, "lookup", map[string]any{"parent_ino": 1, "name": "hello.txt"}, 2)
	if lookup1.P.Err != 0 {
		t.Fatalf("lookup1 err=%d", lookup1.P.Err)
	}
	ino := getResMap(t, lookup1)["entry"].(map[string]any)["ino"].(uint64)

	unlink := send(service, "unlink", map[string]any{"parent_ino": 1, "name": "hello.txt"}, 3)
	if unlink.P.Err != 0 {
		t.Fatalf("unlink err=%d", unlink.P.Err)
	}

	lookup2 := send(service, "lookup", map[string]any{"parent_ino": 1, "name": "hello.txt"}, 4)
	if lookup2.P.Err != int(syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %d", lookup2.P.Err)
	}
	if getResMap(t, lookup2)["entry_ttl_ms"].(int) != 250 {
		t.Fatalf("expected negative ttl=250")
	}

	getattr := send(service, "getattr", map[string]any{"ino": ino}, 5)
	if getattr.P.Err != int(syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %d", getattr.P.Err)
	}
}

func TestFsRpcRenameAcrossDirsPreservesInoAndUpdatesMapping(t *testing.T) {
	service := createService()
	defer service.Close()

	dirA := send(service, "mkdir", map[string]any{"parent_ino": 1, "name": "a", "mode": 0o755}, 1)
	inoA := getResMap(t, dirA)["entry"].(map[string]any)["ino"].(uint64)
	dirB := send(service, "mkdir", map[string]any{"parent_ino": 1, "name": "b", "mode": 0o755}, 2)
	inoB := getResMap(t, dirB)["entry"].(map[string]any)["ino"].(uint64)

	_ = send(service, "create", map[string]any{"parent_ino": inoA, "name": "file.txt", "mode": 0o644, "flags": 0}, 3)

	lookupOld := send(service, "lookup", map[string]any{"parent_ino": inoA, "name": "file.txt"}, 4)
	inoFile := getResMap(t, lookupOld)["entry"].(map[string]any)["ino"].(uint64)

	rename := send(service, "rename", map[string]any{"old_parent_ino": inoA, "old_name": "file.txt", "new_parent_ino": inoB, "new_name": "renamed.txt", "flags": 0}, 5)
	if rename.P.Err != 0 {
		t.Fatalf("rename err=%d", rename.P.Err)
	}

	lookupNew := send(service, "lookup", map[string]any{"parent_ino": inoB, "name": "renamed.txt"}, 6)
	if lookupNew.P.Err != 0 {
		t.Fatalf("lookupNew err=%d", lookupNew.P.Err)
	}
	if getResMap(t, lookupNew)["entry"].(map[string]any)["ino"].(uint64) != inoFile {
		t.Fatalf("expected ino preserved")
	}

	lookupGone := send(service, "lookup", map[string]any{"parent_ino": inoA, "name": "file.txt"}, 7)
	if lookupGone.P.Err != int(syscall.ENOENT) {
		t.Fatalf("expected ENOENT")
	}

	trunc := send(service, "truncate", map[string]any{"ino": inoFile, "size": 0}, 8)
	if trunc.P.Err != 0 {
		t.Fatalf("truncate err=%d", trunc.P.Err)
	}
}

func TestFsRpcOpenFlags(t *testing.T) {
	service := createService()
	defer service.Close()

	created := send(service, "create", map[string]any{"parent_ino": 1, "name": "f.txt", "mode": 0o644, "flags": 0}, 1)
	fh := getResMap(t, created)["fh"].(uint64)
	_ = send(service, "write", map[string]any{"fh": fh, "offset": 0, "data": []byte("hello")}, 2)
	_ = send(service, "release", map[string]any{"fh": fh}, 3)

	lookup := send(service, "lookup", map[string]any{"parent_ino": 1, "name": "f.txt"}, 4)
	ino := getResMap(t, lookup)["entry"].(map[string]any)["ino"].(uint64)

	openCreat := send(service, "open", map[string]any{"ino": ino, "flags": linuxTestOpenFlags.O_CREAT | linuxTestOpenFlags.O_WRONLY}, 5)
	if openCreat.P.Err != int(syscall.EINVAL) {
		t.Fatalf("expected EINVAL, got %d", openCreat.P.Err)
	}

	openTrunc := send(service, "open", map[string]any{"ino": ino, "flags": linuxTestOpenFlags.O_WRONLY | linuxTestOpenFlags.O_TRUNC}, 6)
	if openTrunc.P.Err != 0 {
		t.Fatalf("openTrunc err=%d", openTrunc.P.Err)
	}
	fhTrunc := getResMap(t, openTrunc)["fh"].(uint64)

	readEmpty := send(service, "read", map[string]any{"fh": fhTrunc, "offset": 0, "size": 10}, 7)
	if readEmpty.P.Err != 0 {
		t.Fatalf("readEmpty err=%d", readEmpty.P.Err)
	}
	if len(getResMap(t, readEmpty)["data"].([]byte)) != 0 {
		t.Fatalf("expected empty")
	}

	_ = send(service, "write", map[string]any{"fh": fhTrunc, "offset": 0, "data": []byte("a")}, 8)
	_ = send(service, "release", map[string]any{"fh": fhTrunc}, 9)

	openAppend := send(service, "open", map[string]any{"ino": ino, "flags": linuxTestOpenFlags.O_WRONLY | linuxTestOpenFlags.O_APPEND}, 10)
	if openAppend.P.Err != 0 {
		t.Fatalf("openAppend err=%d", openAppend.P.Err)
	}
	fhAppend := getResMap(t, openAppend)["fh"].(uint64)
	_ = send(service, "write", map[string]any{"fh": fhAppend, "offset": 0, "data": []byte("b")}, 11)
	_ = send(service, "release", map[string]any{"fh": fhAppend}, 12)

	openRead := send(service, "open", map[string]any{"ino": ino, "flags": linuxTestOpenFlags.O_RDONLY}, 13)
	if openRead.P.Err != 0 {
		t.Fatalf("openRead err=%d", openRead.P.Err)
	}
	fhRead := getResMap(t, openRead)["fh"].(uint64)
	read := send(service, "read", map[string]any{"fh": fhRead, "offset": 0, "size": 10}, 14)
	if read.P.Err != 0 {
		t.Fatalf("read err=%d", read.P.Err)
	}
	if string(getResMap(t, read)["data"].([]byte)) != "ab" {
		t.Fatalf("expected ab")
	}
	_ = send(service, "release", map[string]any{"fh": fhRead}, 15)
}

func TestFsRpcMetricsTrackOpsBytesAndErrors(t *testing.T) {
	service := createService()
	defer service.Close()

	created := send(service, "create", map[string]any{"parent_ino": 1, "name": "m.txt", "mode": 0o644, "flags": 0}, 1)
	fh := getResMap(t, created)["fh"].(uint64)

	_ = send(service, "write", map[string]any{"fh": fh, "offset": 0, "data": []byte("abc")}, 2)
	_ = send(service, "read", map[string]any{"fh": fh, "offset": 0, "size": 2}, 3)
	_ = send(service, "read", map[string]any{"fh": uint64(9999), "offset": 0, "size": 1}, 4)

	if service.Metrics.BytesWritten != 3 {
		t.Fatalf("expected bytesWritten=3, got %d", service.Metrics.BytesWritten)
	}
	if service.Metrics.BytesRead != 2 {
		t.Fatalf("expected bytesRead=2, got %d", service.Metrics.BytesRead)
	}
	if service.Metrics.Ops["create"] != 1 {
		t.Fatalf("expected create ops=1")
	}
	if service.Metrics.Ops["write"] != 1 {
		t.Fatalf("expected write ops=1")
	}
	if service.Metrics.Ops["read"] != 2 {
		t.Fatalf("expected read ops=2")
	}
	if service.Metrics.Errors != 1 {
		t.Fatalf("expected errors=1")
	}
	if service.Metrics.Requests != 4 {
		t.Fatalf("expected requests=4, got %d", service.Metrics.Requests)
	}

	_ = send(service, "release", map[string]any{"fh": fh}, 5)
}

type statErrorProvider struct {
	base VirtualProvider
	err  error
}

func (p *statErrorProvider) Readonly() bool         { return p.base.Readonly() }
func (p *statErrorProvider) SupportsSymlinks() bool { return p.base.SupportsSymlinks() }
func (p *statErrorProvider) SupportsWatch() bool    { return p.base.SupportsWatch() }
func (p *statErrorProvider) Open(path string, flags string, mode uint32) (VirtualFileHandle, error) {
	return p.base.Open(path, flags, mode)
}
func (p *statErrorProvider) Stat(_ string) (Stats, error)          { return Stats{}, p.err }
func (p *statErrorProvider) Lstat(path string) (Stats, error)      { return p.base.Lstat(path) }
func (p *statErrorProvider) ReadDir(path string) ([]Dirent, error) { return p.base.ReadDir(path) }
func (p *statErrorProvider) Mkdir(path string, mode uint32) error  { return p.base.Mkdir(path, mode) }
func (p *statErrorProvider) Rmdir(path string) error               { return p.base.Rmdir(path) }
func (p *statErrorProvider) Unlink(path string) error              { return p.base.Unlink(path) }
func (p *statErrorProvider) Rename(oldPath string, newPath string) error {
	return p.base.Rename(oldPath, newPath)
}
func (p *statErrorProvider) Readlink(path string) (string, error) { return p.base.Readlink(path) }
func (p *statErrorProvider) Symlink(target string, path string) error {
	return p.base.Symlink(target, path)
}
func (p *statErrorProvider) Realpath(path string) (string, error)  { return p.base.Realpath(path) }
func (p *statErrorProvider) Access(path string, mode uint32) error { return p.base.Access(path, mode) }
func (p *statErrorProvider) Truncate(path string, size int64) error {
	return p.base.Truncate(path, size)
}
func (p *statErrorProvider) Close() error { return p.base.Close() }

func TestFsRpcNormalizeErrorIncludesMessageAndMapsUnknownToEIO(t *testing.T) {
	base := NewMemoryProvider()
	provider := &statErrorProvider{base: base, err: &ErrnoError{Errno: int(syscall.EPERM), Message: "nope"}}
	service := NewFsRpcService(provider, FsRpcServiceOptions{})
	defer service.Close()

	res := send(service, "getattr", map[string]any{"ino": 1}, 1)
	if res.P.Err != int(syscall.EPERM) {
		t.Fatalf("expected EPERM, got %d", res.P.Err)
	}
	if res.P.Message != "nope" {
		t.Fatalf("expected message nope, got %q", res.P.Message)
	}

	provider2 := &statErrorProvider{base: base, err: errors.New("boom")}
	service2 := NewFsRpcService(provider2, FsRpcServiceOptions{})
	defer service2.Close()

	res2 := send(service2, "getattr", map[string]any{"ino": 1}, 1)
	if res2.P.Err != int(syscall.EIO) {
		t.Fatalf("expected EIO, got %d", res2.P.Err)
	}
	if res2.P.Message == "" {
		t.Fatalf("expected non-empty message")
	}
}

type trackedHandle struct {
	inner      VirtualFileHandle
	closeCount *int
}

func (h *trackedHandle) Path() string          { return h.inner.Path() }
func (h *trackedHandle) Flags() string         { return h.inner.Flags() }
func (h *trackedHandle) Mode() uint32          { return h.inner.Mode() }
func (h *trackedHandle) Position() int64       { return h.inner.Position() }
func (h *trackedHandle) SetPosition(pos int64) { h.inner.SetPosition(pos) }
func (h *trackedHandle) Closed() bool          { return h.inner.Closed() }
func (h *trackedHandle) Read(buf []byte, offset, length int, position *int64) (int, error) {
	return h.inner.Read(buf, offset, length, position)
}
func (h *trackedHandle) Write(buf []byte, offset, length int, position *int64) (int, error) {
	return h.inner.Write(buf, offset, length, position)
}
func (h *trackedHandle) ReadFile() ([]byte, error)   { return h.inner.ReadFile() }
func (h *trackedHandle) WriteFile(data []byte) error { return h.inner.WriteFile(data) }
func (h *trackedHandle) Stat() (Stats, error)        { return h.inner.Stat() }
func (h *trackedHandle) Truncate(size int64) error   { return h.inner.Truncate(size) }
func (h *trackedHandle) Close() error {
	*h.closeCount = *h.closeCount + 1
	return h.inner.Close()
}

type trackedProvider struct {
	base       *MemoryProvider
	closeCount *int
}

func (p *trackedProvider) Readonly() bool         { return p.base.Readonly() }
func (p *trackedProvider) SupportsSymlinks() bool { return p.base.SupportsSymlinks() }
func (p *trackedProvider) SupportsWatch() bool    { return p.base.SupportsWatch() }
func (p *trackedProvider) Open(path string, flags string, mode uint32) (VirtualFileHandle, error) {
	h, err := p.base.Open(path, flags, mode)
	if err != nil {
		return nil, err
	}
	return &trackedHandle{inner: h, closeCount: p.closeCount}, nil
}
func (p *trackedProvider) Stat(path string) (Stats, error)       { return p.base.Stat(path) }
func (p *trackedProvider) Lstat(path string) (Stats, error)      { return p.base.Lstat(path) }
func (p *trackedProvider) ReadDir(path string) ([]Dirent, error) { return p.base.ReadDir(path) }
func (p *trackedProvider) Mkdir(path string, mode uint32) error  { return p.base.Mkdir(path, mode) }
func (p *trackedProvider) Rmdir(path string) error               { return p.base.Rmdir(path) }
func (p *trackedProvider) Unlink(path string) error              { return p.base.Unlink(path) }
func (p *trackedProvider) Rename(oldPath, newPath string) error {
	return p.base.Rename(oldPath, newPath)
}
func (p *trackedProvider) Readlink(path string) (string, error)   { return p.base.Readlink(path) }
func (p *trackedProvider) Symlink(target, path string) error      { return p.base.Symlink(target, path) }
func (p *trackedProvider) Realpath(path string) (string, error)   { return p.base.Realpath(path) }
func (p *trackedProvider) Access(path string, mode uint32) error  { return p.base.Access(path, mode) }
func (p *trackedProvider) Truncate(path string, size int64) error { return p.base.Truncate(path, size) }
func (p *trackedProvider) Close() error                           { return p.base.Close() }

func TestFsRpcServiceCloseClosesAllOpenHandles(t *testing.T) {
	base := NewMemoryProvider()
	closeCount := 0
	provider := &trackedProvider{base: base, closeCount: &closeCount}
	service := NewFsRpcService(provider, FsRpcServiceOptions{})

	created := send(service, "create", map[string]any{"parent_ino": 1, "name": "x.txt", "mode": 0o644, "flags": 0}, 1)
	if created.P.Err != 0 {
		t.Fatalf("create err=%d", created.P.Err)
	}
	fh := getResMap(t, created)["fh"].(uint64)

	_ = service.Close()
	if closeCount != 1 {
		t.Fatalf("expected closeCount=1, got %d", closeCount)
	}

	after := send(service, "release", map[string]any{"fh": fh}, 2)
	if after.P.Err != int(syscall.EBADF) {
		t.Fatalf("expected EBADF, got %d", after.P.Err)
	}
}

func TestFsRpcResponseShapeIsStable(t *testing.T) {
	service := createService()
	defer service.Close()

	res := send(service, "lookup", map[string]any{"parent_ino": 1, "name": "missing"}, 1)
	if res.V != 1 || res.T != "fs_response" || res.ID != 1 {
		t.Fatalf("unexpected envelope: %#v", res)
	}
	if res.P.Op != "lookup" {
		t.Fatalf("unexpected op")
	}
	if res.P.Err != int(syscall.ENOENT) {
		t.Fatalf("expected ENOENT")
	}
	if res.P.Res == nil {
		t.Fatalf("expected res")
	}
	// lookup ENOENT includes negative ttl
	if res.P.Res["entry_ttl_ms"].(int) != DefaultNegativeTTLms {
		t.Fatalf("expected entry_ttl_ms")
	}

	// Ensure ops map is deterministic-ish
	if service.Metrics.Ops["lookup"] != 1 {
		t.Fatalf("expected lookup op count")
	}

	// Verify response doesn't contain unexpected extra fields
	_ = reflect.ValueOf(res)
}
