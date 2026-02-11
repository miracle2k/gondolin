package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/earendil-works/gondolin-go/qemunet"
	"github.com/earendil-works/gondolin-go/vfs"
	"github.com/earendil-works/gondolin-go/virtio"
)

const (
	defaultVfsReadyTimeout = 30 * time.Second
	defaultStdinChunkSize  = 32 * 1024
)

// SandboxServerOptions configure a SandboxServer.
type SandboxServerOptions struct {
	/** qemu binary path (defaults to qemu-system-aarch64 / qemu-system-x86_64) */
	QemuPath string

	/** asset directory containing manifest.json or default filenames */
	ImagePath string
	/** explicit kernel path (overrides ImagePath) */
	KernelPath string
	/** explicit initrd path (overrides ImagePath) */
	InitrdPath string
	/** explicit rootfs path (overrides ImagePath) */
	RootfsPath string

	/** vm memory size (qemu syntax, default: 1G) */
	Memory string
	/** vm cpu count (default: 2) */
	Cpus int

	/** unix socket path for virtio control port */
	VirtioSocketPath string
	/** unix socket path for virtio fs RPC */
	VirtioFsSocketPath string
	/** unix socket path for virtio ssh/tcp-forward */
	VirtioSshSocketPath string

	/** qemu net socket path (optional) */
	NetSocketPath string
	/** guest mac address (qemu syntax, default: 02:00:00:00:00:01) */
	NetMac string
	/** enable qemu net device */
	NetEnabled bool
	/** dns configuration for host network backend */
	Dns qemunet.DnsOptions
	/** custom fetch implementation for HTTP mediation */
	Fetch qemunet.HttpFetch
	/** HTTP allow/request/response hooks */
	HttpHooks qemunet.HttpHooks
	/** mitm ca directory path */
	MitmCertDir string
	/** max intercepted HTTP request body size in `bytes` */
	MaxHttpBodyBytes int
	/** max buffered upstream HTTP response body size in `bytes` */
	MaxHttpResponseBodyBytes int
	/** max buffered guest->upstream TCP write bytes per session in `bytes` */
	MaxTcpPendingWriteBytes int

	/** qemu machine type */
	MachineType string
	/** qemu acceleration backend */
	Accel string
	/** qemu cpu model */
	CPU string
	/** guest console mode */
	Console string // "stdio" | "none"
	/** whether to auto-restart qemu */
	AutoRestart bool

	/** base kernel cmdline append string */
	Append string
	/** enable overlayfs for root (tmpfs upperdir) */
	RootOverlayTmpfs bool

	/** max buffered stdin chunk size in `bytes` (defaults to 32KiB per frame) */
	StdinChunkBytes int

	/** vfs provider (nil disables sandboxfs integration; guest will report vfs_error) */
	VfsProvider vfs.VirtualProvider
}

type sandboxFsConfig struct {
	fuseMount string
	fuseBinds []string
}

// SandboxServer is the host-side controller that bridges the guest virtio protocol.
//
// It is a Go equivalent of host/src/sandbox-server.ts.
type SandboxServer struct {
	options SandboxServerOptions

	controller *SandboxController

	controlBridge *virtio.Bridge
	fsBridge      *virtio.Bridge
	sshBridge     *virtio.Bridge
	network       *qemunet.SocketBackend

	bootMu     sync.Mutex
	baseAppend string
	bootConfig *sandboxFsConfig

	readyMu   sync.Mutex
	readyOnce sync.Once
	readyCh   chan struct{}
	readyErr  error

	fsService *vfs.FsRpcService

	sessionsMu sync.Mutex
	sessions   map[uint32]*execSession
	nextID     uint32

	tcpMu          sync.Mutex
	tcpStreams     map[uint32]*tcpForwardStream
	tcpOpenWaiters map[uint32]chan error
	nextTcpID      uint32

	tmpDir string

	stdinChunk int
}

type execSession struct {
	id uint32

	mu     sync.Mutex
	stdout []byte
	stderr []byte

	doneCh chan execDone
	errCh  chan error
}

type execDone struct {
	exitCode int
	signal   int
}

// NewSandboxServer resolves options, creates bridges, and wires handlers.
//
// It does not start QEMU until Boot() is called.
func NewSandboxServer(options SandboxServerOptions) (*SandboxServer, error) {
	resolved := options

	// Resolve qemu path.
	if resolved.QemuPath == "" {
		bin := "qemu-system-aarch64"
		if detectHostArch() == "x64" {
			bin = "qemu-system-x86_64"
		}
		if p, err := exec.LookPath(bin); err == nil {
			resolved.QemuPath = p
		} else {
			resolved.QemuPath = bin
		}
	}

	// Resolve assets.
	if resolved.KernelPath == "" || resolved.InitrdPath == "" || resolved.RootfsPath == "" {
		assetDir := resolved.ImagePath
		if assetDir == "" {
			assetDir = os.Getenv("GONDOLIN_GUEST_DIR")
		}
		if assetDir == "" {
			return nil, errors.New("missing guest assets: set ImagePath or GONDOLIN_GUEST_DIR or pass explicit KernelPath/InitrdPath/RootfsPath")
		}
		assets, err := LoadGuestAssets(assetDir)
		if err != nil {
			return nil, err
		}
		if resolved.KernelPath == "" {
			resolved.KernelPath = assets.KernelPath
		}
		if resolved.InitrdPath == "" {
			resolved.InitrdPath = assets.InitrdPath
		}
		if resolved.RootfsPath == "" {
			resolved.RootfsPath = assets.RootfsPath
		}
	}

	// Temp dir for sockets.
	tmpDir, err := os.MkdirTemp("", "gondolin-go-")
	if err != nil {
		return nil, err
	}

	if resolved.VirtioSocketPath == "" {
		resolved.VirtioSocketPath = filepath.Join(tmpDir, "virtio.sock")
	}
	if resolved.VirtioFsSocketPath == "" {
		resolved.VirtioFsSocketPath = filepath.Join(tmpDir, "virtiofs.sock")
	}
	if resolved.VirtioSshSocketPath == "" {
		resolved.VirtioSshSocketPath = filepath.Join(tmpDir, "virtiossh.sock")
	}

	if resolved.NetEnabled {
		if resolved.NetSocketPath == "" {
			resolved.NetSocketPath = filepath.Join(tmpDir, "net.sock")
		}
		if resolved.NetMac == "" {
			resolved.NetMac = "02:00:00:00:00:01"
		}
	}

	stdinChunk := resolved.StdinChunkBytes
	if stdinChunk <= 0 {
		stdinChunk = defaultStdinChunkSize
	}

	// Base append.
	consoleDevice := "ttyS0"
	if detectHostArch() == "arm64" {
		consoleDevice = "ttyAMA0"
	}

	baseAppend := strings.TrimSpace(resolved.Append)
	if baseAppend == "" {
		baseAppend = fmt.Sprintf("console=%s initramfs_async=1", consoleDevice)
	}
	if resolved.RootOverlayTmpfs {
		parts := strings.Fields(baseAppend)
		has := false
		for _, p := range parts {
			if strings.HasPrefix(p, "root.overlay=") {
				has = true
				break
			}
		}
		if !has {
			baseAppend = strings.TrimSpace(baseAppend + " root.overlay=tmpfs")
		}
	}

	server := &SandboxServer{
		options:        resolved,
		controlBridge:  virtio.NewBridge(resolved.VirtioSocketPath, virtio.BridgeOptions{MaxPendingBytes: max(8*1024*1024, stdinChunk*2)}),
		fsBridge:       virtio.NewBridge(resolved.VirtioFsSocketPath, virtio.BridgeOptions{MaxPendingBytes: 8 * 1024 * 1024}),
		sshBridge:      virtio.NewBridge(resolved.VirtioSshSocketPath, virtio.BridgeOptions{MaxPendingBytes: 64 * 1024 * 1024}),
		readyCh:        make(chan struct{}),
		sessions:       map[uint32]*execSession{},
		nextID:         1,
		tcpStreams:     map[uint32]*tcpForwardStream{},
		tcpOpenWaiters: map[uint32]chan error{},
		nextTcpID:      1,
		tmpDir:         tmpDir,
		stdinChunk:     stdinChunk,
		baseAppend:     baseAppend,
	}

	if resolved.VfsProvider != nil {
		server.fsService = vfs.NewFsRpcService(resolved.VfsProvider, vfs.FsRpcServiceOptions{})
	}

	controllerCfg := SandboxConfig{
		QemuPath:            resolved.QemuPath,
		KernelPath:          resolved.KernelPath,
		InitrdPath:          resolved.InitrdPath,
		RootfsPath:          resolved.RootfsPath,
		Memory:              resolved.Memory,
		Cpus:                resolved.Cpus,
		VirtioSocketPath:    resolved.VirtioSocketPath,
		VirtioFsSocketPath:  resolved.VirtioFsSocketPath,
		VirtioSshSocketPath: resolved.VirtioSshSocketPath,
		Append:              baseAppend,
		MachineType:         resolved.MachineType,
		Accel:               resolved.Accel,
		CPU:                 resolved.CPU,
		Console:             resolved.Console,
		NetSocketPath:       ternary(resolved.NetEnabled, resolved.NetSocketPath, ""),
		NetMac:              resolved.NetMac,
		AutoRestart:         resolved.AutoRestart,
	}
	server.controller = NewSandboxController(controllerCfg)

	if resolved.NetEnabled {
		netOpts := qemunet.QemuNetworkOptions{
			SocketPath:               resolved.NetSocketPath,
			Dns:                      resolved.Dns,
			Fetch:                    resolved.Fetch,
			HttpHooks:                resolved.HttpHooks,
			MitmCertDir:              resolved.MitmCertDir,
			MaxHttpBodyBytes:         resolved.MaxHttpBodyBytes,
			MaxHttpResponseBodyBytes: resolved.MaxHttpResponseBodyBytes,
			MaxTCPPendingWriteBytes:  resolved.MaxTcpPendingWriteBytes,
		}
		if mac := parseMacAddress(resolved.NetMac); len(mac) == 6 {
			netOpts.VmMac = mac
		}
		network, err := qemunet.NewSocketBackend(netOpts)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		server.network = network
	}

	server.wireHandlers()

	return server, nil
}

func (s *SandboxServer) wireHandlers() {
	s.controlBridge.SetHandlers(s.handleControlMessage, func(err error) {
		// Ignore benign shutdown errors.
		_ = err
	})

	s.fsBridge.SetHandlers(s.handleFsMessage, func(err error) {
		_ = err
	})

	s.sshBridge.SetHandlers(s.handleSshMessage, func(err error) {
		_ = err
	})
}

// Boot configures sandboxfs mount/bind paths and starts (or restarts) QEMU.
func (s *SandboxServer) Boot(ctx context.Context, fuseMount string, fuseBinds []string) error {
	cfg, err := normalizeSandboxFsConfig(fuseMount, fuseBinds)
	if err != nil {
		return err
	}

	s.bootMu.Lock()
	changed := s.bootConfig == nil || !sameSandboxFsConfig(*s.bootConfig, cfg)
	s.bootConfig = &cfg
	append := buildSandboxfsAppend(s.baseAppend, cfg)
	s.controller.SetAppend(append)
	s.bootMu.Unlock()

	state := s.controller.State()
	if changed {
		if state == SandboxRunning || state == SandboxStarting {
			s.resetReady()
			if err := s.controller.Restart(); err != nil {
				return err
			}
			return s.WaitReady(ctx)
		}
	}

	if state == SandboxStopped {
		s.resetReady()
		if err := s.startBridges(); err != nil {
			return err
		}
		if err := s.controller.Start(); err != nil {
			return err
		}
	}

	return s.WaitReady(ctx)
}

func (s *SandboxServer) startBridges() error {
	if err := s.fsBridge.Start(); err != nil {
		return err
	}
	if err := s.controlBridge.Start(); err != nil {
		return err
	}
	if err := s.sshBridge.Start(); err != nil {
		return err
	}
	if s.network != nil {
		if err := s.network.Start(); err != nil {
			return err
		}
	}
	return nil
}

// WaitReady waits for the guest to send vfs_ready or vfs_error.
func (s *SandboxServer) WaitReady(ctx context.Context) error {
	// If Boot wasn't called, nothing will ever become ready.
	s.bootMu.Lock()
	booted := s.bootConfig != nil
	s.bootMu.Unlock()
	if !booted {
		return errors.New("missing boot configuration")
	}

	s.readyMu.Lock()
	ch := s.readyCh
	s.readyMu.Unlock()

	select {
	case <-ch:
		s.readyMu.Lock()
		err := s.readyErr
		s.readyMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(defaultVfsReadyTimeout):
		return errors.New("vfs_ready timeout")
	}
}

func (s *SandboxServer) resetReady() {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	s.readyOnce = sync.Once{}
	s.readyErr = nil
	s.readyCh = make(chan struct{})
}

func (s *SandboxServer) markReady(err error) {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	s.readyOnce.Do(func() {
		s.readyErr = err
		close(s.readyCh)
	})
}

// Close stops QEMU and closes all bridges.
func (s *SandboxServer) Close() error {
	_ = s.controller.Close()
	_ = s.controlBridge.Close()
	_ = s.fsBridge.Close()
	_ = s.sshBridge.Close()
	if s.network != nil {
		_ = s.network.Close()
	}
	if s.fsService != nil {
		_ = s.fsService.Close()
	}
	if s.options.VfsProvider != nil {
		_ = s.options.VfsProvider.Close()
	}
	if s.tmpDir != "" {
		_ = os.RemoveAll(s.tmpDir)
	}
	return nil
}

// Exec executes a command inside the guest via the virtio exec protocol.
func (s *SandboxServer) Exec(ctx context.Context, req ExecRequest) (ExecResult, error) {
	if err := s.WaitReady(ctx); err != nil {
		return ExecResult{}, err
	}

	id := s.allocExecID()
	sess := &execSession{id: id, doneCh: make(chan execDone, 1), errCh: make(chan error, 1)}

	s.sessionsMu.Lock()
	s.sessions[id] = sess
	s.sessionsMu.Unlock()

	argv := req.Argv
	if argv == nil {
		argv = []string{}
	}
	env := req.Env
	if env == nil {
		env = []string{}
	}

	payload := map[string]any{
		"cmd":   req.Cmd,
		"argv":  argv,
		"env":   env,
		"cwd":   req.Cwd,
		"stdin": req.Stdin != nil,
		"pty":   req.Pty,
	}

	if err := s.controlBridge.Send(virtio.Envelope{V: 1, T: "exec_request", ID: id, P: payload}); err != nil {
		s.sessionsMu.Lock()
		delete(s.sessions, id)
		s.sessionsMu.Unlock()
		return ExecResult{}, err
	}

	if req.Stdin != nil {
		if err := s.sendStdin(ctx, id, req.Stdin); err != nil {
			// Don't delete session here; the guest may still respond.
			return ExecResult{}, err
		}
	}

	select {
	case done := <-sess.doneCh:
		s.sessionsMu.Lock()
		delete(s.sessions, id)
		s.sessionsMu.Unlock()

		sess.mu.Lock()
		out := append([]byte(nil), sess.stdout...)
		errOut := append([]byte(nil), sess.stderr...)
		sess.mu.Unlock()

		return ExecResult{ExitCode: done.exitCode, Signal: done.signal, Stdout: out, Stderr: errOut}, nil
	case err := <-sess.errCh:
		s.sessionsMu.Lock()
		delete(s.sessions, id)
		s.sessionsMu.Unlock()
		return ExecResult{}, err
	case <-ctx.Done():
		return ExecResult{}, ctx.Err()
	}
}

func (s *SandboxServer) sendStdin(ctx context.Context, id uint32, r io.Reader) error {
	buf := make([]byte, s.stdinChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := s.controlBridge.Send(virtio.Envelope{V: 1, T: "stdin_data", ID: id, P: map[string]any{"data": chunk}}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// send EOF
				return s.controlBridge.Send(virtio.Envelope{V: 1, T: "stdin_data", ID: id, P: map[string]any{"data": []byte{}, "eof": true}})
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (s *SandboxServer) allocExecID() uint32 {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	id := s.nextID
	for i := 0; i < 0xffffffff; i++ {
		if id == 0 {
			id = 1
		}
		if _, ok := s.sessions[id]; !ok {
			break
		}
		id++
	}
	s.nextID = id + 1
	if s.nextID == 0 {
		s.nextID = 1
	}
	return id
}

func (s *SandboxServer) handleControlMessage(env virtio.Envelope) {
	switch env.T {
	case "exec_output":
		stream, _ := env.P["stream"].(string)
		data, _ := env.P["data"].([]byte)

		s.sessionsMu.Lock()
		sess := s.sessions[env.ID]
		s.sessionsMu.Unlock()
		if sess == nil || len(data) == 0 {
			return
		}

		sess.mu.Lock()
		if stream == "stderr" {
			sess.stderr = append(sess.stderr, data...)
		} else {
			sess.stdout = append(sess.stdout, data...)
		}
		sess.mu.Unlock()

	case "exec_response":
		exitCode := int(asUint(env.P["exit_code"]))
		signal := int(asUint(env.P["signal"]))

		s.sessionsMu.Lock()
		sess := s.sessions[env.ID]
		s.sessionsMu.Unlock()
		if sess == nil {
			return
		}
		sess.doneCh <- execDone{exitCode: exitCode, signal: signal}

	case "error":
		code, _ := env.P["code"].(string)
		msg, _ := env.P["message"].(string)
		err := fmt.Errorf("guest error %s: %s", code, msg)

		if env.ID != 0 {
			s.sessionsMu.Lock()
			sess := s.sessions[env.ID]
			s.sessionsMu.Unlock()
			if sess != nil {
				sess.errCh <- err
				return
			}
		}

		// Uncorrelated error (e.g. boot failure)
		s.markReady(err)

	case "vfs_ready":
		s.markReady(nil)

	case "vfs_error":
		msg, _ := env.P["message"].(string)
		if msg == "" {
			msg = "vfs error"
		}
		s.markReady(errors.New(msg))
	}
}

func (s *SandboxServer) handleFsMessage(env virtio.Envelope) {
	if env.T != "fs_request" {
		return
	}

	op, _ := env.P["op"].(string)
	reqMap, _ := env.P["req"].(map[string]any)

	if s.fsService == nil {
		_ = s.fsBridge.Send(virtio.Envelope{V: 1, T: "fs_response", ID: env.ID, P: map[string]any{"op": op, "err": int(syscall.ENOSYS), "message": "filesystem service unavailable"}})
		return
	}

	// Run handler in a goroutine to avoid blocking the bridge reader loop.
	go func() {
		msg := vfs.FsRequest{V: 1, T: "fs_request", ID: env.ID}
		msg.P.Op = op
		msg.P.Req = reqMap

		resp := s.fsService.HandleRequest(msg)
		p := map[string]any{"op": resp.P.Op, "err": resp.P.Err}
		if resp.P.Res != nil {
			p["res"] = resp.P.Res
		}
		if resp.P.Message != "" {
			p["message"] = resp.P.Message
		}

		_ = s.fsBridge.Send(virtio.Envelope{V: 1, T: "fs_response", ID: env.ID, P: p})
	}()
}

func (s *SandboxServer) handleSshMessage(env virtio.Envelope) {
	switch env.T {
	case "tcp_opened":
		ok := false
		if v, okAny := env.P["ok"].(bool); okAny {
			ok = v
		}
		message, _ := env.P["message"].(string)

		s.tcpMu.Lock()
		waiter := s.tcpOpenWaiters[env.ID]
		if waiter != nil {
			delete(s.tcpOpenWaiters, env.ID)
		}
		s.tcpMu.Unlock()

		if waiter != nil {
			if ok {
				waiter <- nil
			} else {
				if message == "" {
					message = "tcp_open failed"
				}
				waiter <- errors.New(message)
			}
		}

	case "tcp_data":
		data, _ := env.P["data"].([]byte)
		s.tcpMu.Lock()
		stream := s.tcpStreams[env.ID]
		s.tcpMu.Unlock()
		if stream != nil && len(data) > 0 {
			stream.pushRemote(data)
		}

	case "tcp_close":
		s.tcpMu.Lock()
		stream := s.tcpStreams[env.ID]
		delete(s.tcpStreams, env.ID)
		waiter := s.tcpOpenWaiters[env.ID]
		if waiter != nil {
			delete(s.tcpOpenWaiters, env.ID)
		}
		s.tcpMu.Unlock()

		if waiter != nil {
			waiter <- errors.New("tcp stream closed")
		}
		if stream != nil {
			stream.remoteClose()
		}
	}
}

// OpenTCPStream opens a loopback TCP stream inside the guest via the virtio-ssh port.
func (s *SandboxServer) OpenTCPStream(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	if err := s.WaitReady(ctx); err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	id := s.allocTcpID()
	stream := newTcpForwardStream(id, s)

	waiter := make(chan error, 1)
	s.tcpMu.Lock()
	s.tcpStreams[id] = stream
	s.tcpOpenWaiters[id] = waiter
	s.tcpMu.Unlock()

	// Send open request.
	if err := s.sshBridge.Send(virtio.Envelope{V: 1, T: "tcp_open", ID: id, P: map[string]any{"host": host, "port": uint64(port)}}); err != nil {
		s.tcpMu.Lock()
		delete(s.tcpStreams, id)
		delete(s.tcpOpenWaiters, id)
		s.tcpMu.Unlock()
		_ = stream.Close()
		return nil, err
	}

	select {
	case err := <-waiter:
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, nil
	case <-ctx.Done():
		_ = stream.Close()
		return nil, ctx.Err()
	}
}

func (s *SandboxServer) allocTcpID() uint32 {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	id := s.nextTcpID
	for i := 0; i < 0xffffffff; i++ {
		if id == 0 {
			id = 1
		}
		if _, ok := s.tcpStreams[id]; !ok {
			if _, ok2 := s.tcpOpenWaiters[id]; !ok2 {
				break
			}
		}
		id++
	}
	s.nextTcpID = id + 1
	if s.nextTcpID == 0 {
		s.nextTcpID = 1
	}
	return id
}

// ExecRequest describes a guest exec request.
type ExecRequest struct {
	Cmd   string
	Argv  []string
	Env   []string
	Cwd   string
	Stdin io.Reader
	Pty   bool
}

// ExecResult is returned by Exec.
type ExecResult struct {
	ExitCode int
	Signal   int
	Stdout   []byte
	Stderr   []byte
}

// Helpers

func normalizeSandboxFsConfig(fuseMount string, fuseBinds []string) (sandboxFsConfig, error) {
	mount, err := vfs.NormalizeMountPath(fuseMount)
	if err != nil {
		return sandboxFsConfig{}, err
	}
	binds := make([]string, 0, len(fuseBinds))
	seen := map[string]struct{}{}
	for _, b := range fuseBinds {
		if b == "" {
			continue
		}
		n, err := vfs.NormalizeMountPath(b)
		if err != nil {
			return sandboxFsConfig{}, err
		}
		if n == "/" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		binds = append(binds, n)
	}
	sort.Strings(binds)
	return sandboxFsConfig{fuseMount: mount, fuseBinds: binds}, nil
}

func sameSandboxFsConfig(a, b sandboxFsConfig) bool {
	if a.fuseMount != b.fuseMount {
		return false
	}
	if len(a.fuseBinds) != len(b.fuseBinds) {
		return false
	}
	for i := range a.fuseBinds {
		if a.fuseBinds[i] != b.fuseBinds[i] {
			return false
		}
	}
	return true
}

func buildSandboxfsAppend(baseAppend string, cfg sandboxFsConfig) string {
	pieces := []string{strings.TrimSpace(baseAppend), fmt.Sprintf("sandboxfs.mount=%s", cfg.fuseMount)}
	if len(cfg.fuseBinds) > 0 {
		pieces = append(pieces, fmt.Sprintf("sandboxfs.bind=%s", strings.Join(cfg.fuseBinds, ",")))
	}
	out := []string{}
	for _, p := range pieces {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.TrimSpace(strings.Join(out, " "))
}

func parseMacAddress(value string) []byte {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return nil
	}
	out := make([]byte, 6)
	for i, part := range parts {
		if len(part) != 2 {
			return nil
		}
		var v byte
		for _, ch := range []byte(strings.ToLower(part)) {
			v <<= 4
			switch {
			case ch >= '0' && ch <= '9':
				v |= ch - '0'
			case ch >= 'a' && ch <= 'f':
				v |= ch - 'a' + 10
			default:
				return nil
			}
		}
		out[i] = v
	}
	return out
}

func asUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint8:
		return uint64(x)
	case int:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case float64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	default:
		return 0
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func detectHostArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	// On macOS under Rosetta, runtime.GOARCH may be amd64 even on arm64 hosts.
	if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" {
		out, err := exec.Command("sysctl", "-n", "hw.optional.arm64").Output()
		if err == nil && strings.TrimSpace(string(out)) == "1" {
			return "arm64"
		}
	}
	return "x64"
}

// tcpForwardStream is a minimal ReadWriteCloser backed by the virtio-ssh tcp_* messages.
//
// It is intentionally small and only supports blocking reads/writes and Close.
// Deadlines and address metadata are not implemented.
type tcpForwardStream struct {
	id uint32
	s  *SandboxServer

	rxCh chan []byte

	mu    sync.Mutex
	rxBuf []byte

	closeOnce sync.Once
	closeCh   chan struct{}
	closed    bool
}

func newTcpForwardStream(id uint32, s *SandboxServer) *tcpForwardStream {
	return &tcpForwardStream{
		id:      id,
		s:       s,
		rxCh:    make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
}

func (t *tcpForwardStream) Read(p []byte) (int, error) {
	for {
		t.mu.Lock()
		if len(t.rxBuf) > 0 {
			n := copy(p, t.rxBuf)
			t.rxBuf = t.rxBuf[n:]
			t.mu.Unlock()
			return n, nil
		}
		closed := t.closed
		t.mu.Unlock()

		if closed {
			return 0, io.EOF
		}

		select {
		case chunk := <-t.rxCh:
			if len(chunk) == 0 {
				continue
			}
			t.mu.Lock()
			t.rxBuf = append(t.rxBuf, chunk...)
			t.mu.Unlock()
		case <-t.closeCh:
			return 0, io.EOF
		}
	}
}

func (t *tcpForwardStream) Write(p []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, errors.New("tcp stream closed")
	}
	t.mu.Unlock()

	chunk := append([]byte(nil), p...)
	if err := t.s.sshBridge.Send(virtio.Envelope{V: 1, T: "tcp_data", ID: t.id, P: map[string]any{"data": chunk}}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *tcpForwardStream) Close() error {
	t.close(true)
	return nil
}

func (t *tcpForwardStream) remoteClose() {
	t.close(false)
}

func (t *tcpForwardStream) close(sendClose bool) {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()

		// Remove from server maps.
		t.s.tcpMu.Lock()
		delete(t.s.tcpStreams, t.id)
		waiter := t.s.tcpOpenWaiters[t.id]
		if waiter != nil {
			delete(t.s.tcpOpenWaiters, t.id)
		}
		t.s.tcpMu.Unlock()

		if waiter != nil {
			waiter <- errors.New("tcp stream closed")
		}

		close(t.closeCh)

		if sendClose {
			_ = t.s.sshBridge.Send(virtio.Envelope{V: 1, T: "tcp_close", ID: t.id, P: map[string]any{}})
		}
	})
}

func (t *tcpForwardStream) pushRemote(data []byte) {
	select {
	case <-t.closeCh:
		return
	default:
	}

	chunk := append([]byte(nil), data...)
	select {
	case t.rxCh <- chunk:
	default:
		// Backpressure: if the local reader is too slow, close the stream.
		t.remoteClose()
	}
}
