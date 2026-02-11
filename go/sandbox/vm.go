package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/earendil-works/gondolin-go/mitm"
	"github.com/earendil-works/gondolin-go/vfs"
)

// VmVfsOptions configure the sandboxfs-backed virtual filesystem.
type VmVfsOptions struct {
	/** mount map (guest path -> provider) */
	Mounts map[string]vfs.VirtualProvider
	/** vfs hook callbacks */
	Hooks vfs.Hooks
	/** guest path for the fuse mount (default: /data) */
	FuseMount string
}

// VMOptions configure a VM.
type VMOptions struct {
	/** sandbox server options */
	Sandbox SandboxServerOptions
	/** vfs configuration (nil uses defaults) */
	Vfs *VmVfsOptions
	/** default environment variables */
	Env map[string]string
	/** override for mounting mitm CA at /etc/ssl/certs (default: enabled when networking is enabled) */
	EnableMitmCertMount *bool
	/** mitm ca directory path */
	MitmCertDir string
}

// VM is a high-level Go wrapper around SandboxServer.
//
// It is analogous to host/src/vm.ts in the TypeScript SDK but currently focuses on
// VM lifecycle and exec.
type VM struct {
	server     *SandboxServer
	defaultEnv map[string]string
}

func CreateVM(ctx context.Context, options VMOptions) (*VM, error) {
	mounts := map[string]vfs.VirtualProvider{}
	if options.Vfs != nil && options.Vfs.Mounts != nil {
		for k, v := range options.Vfs.Mounts {
			mounts[k] = v
		}
	}

	// Optional mitm CA mount.
	enableMitmMount := options.Sandbox.NetEnabled
	if options.EnableMitmCertMount != nil {
		enableMitmMount = *options.EnableMitmCertMount
	}
	if enableMitmMount {
		if _, ok := mounts["/etc/ssl/certs"]; !ok {
			provider, err := createMitmCaProvider(options.MitmCertDir)
			if err != nil {
				return nil, err
			}
			mounts["/etc/ssl/certs"] = provider
		}
	}

	if len(mounts) == 0 {
		// Ensure sandboxfs has something to serve.
		mounts["/"] = vfs.NewMemoryProvider()
	} else {
		// Provide a writable root by default if the user only mounted subpaths.
		if _, ok := mounts["/"]; !ok {
			mounts["/"] = vfs.NewMemoryProvider()
		}
	}

	normalized, err := vfs.NormalizeMountMap(mounts)
	if err != nil {
		return nil, err
	}

	// Select provider.
	var provider vfs.VirtualProvider
	if len(normalized) == 1 {
		if p, ok := normalized["/"]; ok {
			provider = p
		} else {
			router, err := vfs.NewMountRouterProvider(normalized)
			if err != nil {
				return nil, err
			}
			provider = router
		}
	} else {
		router, err := vfs.NewMountRouterProvider(normalized)
		if err != nil {
			return nil, err
		}
		provider = router
	}

	// Apply hooks.
	hooks := vfs.Hooks{}
	if options.Vfs != nil {
		hooks = options.Vfs.Hooks
	}
	if hooks.Before != nil || hooks.After != nil {
		if _, ok := provider.(*vfs.SandboxVfsProvider); !ok {
			provider = vfs.NewSandboxVfsProvider(provider, hooks)
		}
	}

	// Fuse mount + binds.
	fuseMount := "/data"
	if options.Vfs != nil && options.Vfs.FuseMount != "" {
		fuseMount = options.Vfs.FuseMount
	}

	mountPaths, err := vfs.ListMountPaths(normalized)
	if err != nil {
		return nil, err
	}
	fuseBinds := make([]string, 0, len(mountPaths))
	for _, p := range mountPaths {
		if p == "/" {
			continue
		}
		fuseBinds = append(fuseBinds, p)
	}
	// Keep stable order.
	sort.Strings(fuseBinds)

	sandboxOpts := options.Sandbox
	sandboxOpts.VfsProvider = provider

	server, err := NewSandboxServer(sandboxOpts)
	if err != nil {
		return nil, err
	}

	if err := server.Boot(ctx, fuseMount, fuseBinds); err != nil {
		_ = server.Close()
		return nil, err
	}

	defaultEnv := map[string]string{}
	for k, v := range options.Env {
		defaultEnv[k] = v
	}

	return &VM{server: server, defaultEnv: defaultEnv}, nil
}

func (v *VM) Close() error {
	if v.server == nil {
		return nil
	}
	err := v.server.Close()
	v.server = nil
	return err
}

type ExecOptions struct {
	Env   map[string]string
	Cwd   string
	Stdin io.Reader
	Pty   bool
}

func (v *VM) Exec(ctx context.Context, cmd string, argv []string, opts ExecOptions) (ExecResult, error) {
	if v.server == nil {
		return ExecResult{}, errors.New("vm closed")
	}

	env := mergeEnv(v.defaultEnv, opts.Env)
	envList := mapToEnvList(env)

	return v.server.Exec(ctx, ExecRequest{Cmd: cmd, Argv: argv, Env: envList, Cwd: opts.Cwd, Stdin: opts.Stdin, Pty: opts.Pty})
}

// ExecShell runs a command via /bin/sh -lc.
func (v *VM) ExecShell(ctx context.Context, command string, opts ExecOptions) (ExecResult, error) {
	return v.Exec(ctx, "/bin/sh", []string{"-lc", command}, opts)
}

func (v *VM) OpenTCPStream(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	if v.server == nil {
		return nil, errors.New("vm closed")
	}
	return v.server.OpenTCPStream(ctx, host, port)
}

func mergeEnv(base, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func mapToEnvList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%s", k, env[k]))
	}
	return out
}

func createMitmCaProvider(mitmCertDir string) (vfs.VirtualProvider, error) {
	dir := mitm.ResolveMitmCertDir(mitmCertDir)
	ca, err := mitm.LoadOrCreateMitmCa(dir)
	if err != nil {
		return nil, err
	}

	provider := vfs.NewMemoryProvider()
	h, err := provider.Open("/ca-certificates.crt", "w", 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = h.Close() }()

	pem := ca.CertPEM
	if !strings.HasSuffix(pem, "\n") {
		pem += "\n"
	}
	if err := h.WriteFile([]byte(pem)); err != nil {
		return nil, err
	}

	provider.SetReadOnly()
	return provider, nil
}
