package vfs

import (
	"errors"
	"os"
	"sort"
	"strings"
	"syscall"
)

// NormalizeMountPath validates and normalizes a mount path.
func NormalizeMountPath(input string) (string, error) {
	if input == "" {
		return "", errors.New("mount path must be a non-empty string")
	}
	if !strings.HasPrefix(input, "/") {
		return "", errors.New("mount path must be absolute")
	}
	if strings.ContainsRune(input, '\x00') {
		return "", errors.New("mount path contains null bytes")
	}
	return NormalizeVfsPath(input), nil
}

// NormalizeMountMap normalizes mount paths and validates providers.
func NormalizeMountMap(mounts map[string]VirtualProvider) (map[string]VirtualProvider, error) {
	out := map[string]VirtualProvider{}
	for k, v := range mounts {
		if v == nil {
			return nil, errors.New("mount provider is invalid")
		}
		n, err := NormalizeMountPath(k)
		if err != nil {
			return nil, err
		}
		if _, ok := out[n]; ok {
			return nil, errors.New("duplicate mount path")
		}
		out[n] = v
	}
	return out, nil
}

func ListMountPaths(mounts map[string]VirtualProvider) ([]string, error) {
	if mounts == nil {
		return []string{}, nil
	}
	normalized, err := NormalizeMountMap(mounts)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(normalized))
	for k := range normalized {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	return paths, nil
}

// MountRouterProvider routes VFS operations to the provider mounted at the deepest matching mount point.
//
// It also exposes virtual directories for mount boundaries.
type MountRouterProvider struct {
	mountMap    map[string]VirtualProvider
	mountPaths  []string // sorted longest-first
	allReadonly bool
	allSymlinks bool
	allWatch    bool
}

func NewMountRouterProvider(mounts map[string]VirtualProvider) (*MountRouterProvider, error) {
	normalized, err := NormalizeMountMap(mounts)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, errors.New("mounts cannot be empty")
	}

	paths := make([]string, 0, len(normalized))
	providers := make([]VirtualProvider, 0, len(normalized))
	for k, v := range normalized {
		paths = append(paths, k)
		providers = append(providers, v)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })

	allRO := true
	allSymlinks := true
	allWatch := true
	for _, p := range providers {
		if !p.Readonly() {
			allRO = false
		}
		if !p.SupportsSymlinks() {
			allSymlinks = false
		}
		if !p.SupportsWatch() {
			allWatch = false
		}
	}

	return &MountRouterProvider{mountMap: normalized, mountPaths: paths, allReadonly: allRO, allSymlinks: allSymlinks, allWatch: allWatch}, nil
}

func (r *MountRouterProvider) Readonly() bool         { return r.allReadonly }
func (r *MountRouterProvider) SupportsSymlinks() bool { return r.allSymlinks }
func (r *MountRouterProvider) SupportsWatch() bool    { return r.allWatch }

func (r *MountRouterProvider) Open(entryPath string, flags string, mode uint32) (VirtualFileHandle, error) {
	m, err := r.requireMount(entryPath, "open")
	if err != nil {
		return nil, err
	}
	return m.provider.Open(m.relativePath, flags, mode)
}

func (r *MountRouterProvider) Stat(entryPath string) (Stats, error) {
	mount := r.resolveMount(entryPath)
	children := r.virtualChildren(entryPath)

	if mount == nil {
		if len(children) == 0 {
			return Stats{}, CreateErrnoError(int(syscall.ENOENT), "stat", entryPath)
		}
		return createVirtualDirStats(), nil
	}

	// If this is on the root mount and there are virtual children, expose as a virtual dir if base is missing.
	if mount.mountPath == "/" && len(children) > 0 {
		st, err := mount.provider.Stat(mount.relativePath)
		if err != nil {
			if isNoEntryError(err) {
				return createVirtualDirStats(), nil
			}
			return Stats{}, err
		}
		return st, nil
	}

	return mount.provider.Stat(mount.relativePath)
}

func (r *MountRouterProvider) Lstat(entryPath string) (Stats, error) {
	mount := r.resolveMount(entryPath)
	children := r.virtualChildren(entryPath)
	if mount == nil {
		if len(children) == 0 {
			return Stats{}, CreateErrnoError(int(syscall.ENOENT), "lstat", entryPath)
		}
		return createVirtualDirStats(), nil
	}
	if mount.mountPath == "/" && len(children) > 0 {
		st, err := mount.provider.Lstat(mount.relativePath)
		if err != nil {
			if isNoEntryError(err) {
				return createVirtualDirStats(), nil
			}
			return Stats{}, err
		}
		return st, nil
	}
	return mount.provider.Lstat(mount.relativePath)
}

func (r *MountRouterProvider) ReadDir(entryPath string) ([]Dirent, error) {
	mount := r.resolveMount(entryPath)
	children := r.virtualChildren(entryPath)

	if mount == nil {
		if len(children) == 0 {
			return nil, CreateErrnoError(int(syscall.ENOENT), "readdir", entryPath)
		}
		return formatVirtualEntries(children), nil
	}

	entries, err := mount.provider.ReadDir(mount.relativePath)
	if err != nil {
		if isNoEntryError(err) {
			if len(children) > 0 {
				return formatVirtualEntries(children), nil
			}
		}
		return nil, err
	}

	return mergeEntries(entries, children), nil
}

func (r *MountRouterProvider) Mkdir(entryPath string, mode uint32) error {
	m, err := r.requireMount(entryPath, "mkdir")
	if err != nil {
		return err
	}
	return m.provider.Mkdir(m.relativePath, mode)
}

func (r *MountRouterProvider) Rmdir(entryPath string) error {
	m, err := r.requireMount(entryPath, "rmdir")
	if err != nil {
		return err
	}
	return m.provider.Rmdir(m.relativePath)
}

func (r *MountRouterProvider) Unlink(entryPath string) error {
	m, err := r.requireMount(entryPath, "unlink")
	if err != nil {
		return err
	}
	return m.provider.Unlink(m.relativePath)
}

func (r *MountRouterProvider) Rename(oldPath, newPath string) error {
	from, err := r.requireMount(oldPath, "rename")
	if err != nil {
		return err
	}
	to, err := r.requireMount(newPath, "rename")
	if err != nil {
		return err
	}
	if from.mountPath != to.mountPath {
		return CreateErrnoError(int(syscall.EXDEV), "rename", oldPath)
	}
	return from.provider.Rename(from.relativePath, to.relativePath)
}

func (r *MountRouterProvider) Readlink(entryPath string) (string, error) {
	m, err := r.requireMount(entryPath, "readlink")
	if err != nil {
		return "", err
	}
	return m.provider.Readlink(m.relativePath)
}

func (r *MountRouterProvider) Symlink(target, entryPath string) error {
	m, err := r.requireMount(entryPath, "symlink")
	if err != nil {
		return err
	}
	return m.provider.Symlink(target, m.relativePath)
}

func (r *MountRouterProvider) Realpath(entryPath string) (string, error) {
	mount := r.resolveMount(entryPath)
	children := r.virtualChildren(entryPath)
	if mount == nil {
		if len(children) == 0 {
			return "", CreateErrnoError(int(syscall.ENOENT), "realpath", entryPath)
		}
		return NormalizeVfsPath(entryPath), nil
	}
	if mount.mountPath == "/" && len(children) > 0 {
		p, err := mount.provider.Realpath(mount.relativePath)
		if err != nil {
			if isNoEntryError(err) {
				return NormalizeVfsPath(entryPath), nil
			}
			return "", err
		}
		return p, nil
	}
	return mount.provider.Realpath(mount.relativePath)
}

func (r *MountRouterProvider) Access(entryPath string, mode uint32) error {
	mount := r.resolveMount(entryPath)
	children := r.virtualChildren(entryPath)
	if mount == nil {
		if len(children) == 0 {
			return CreateErrnoError(int(syscall.ENOENT), "access", entryPath)
		}
		return nil
	}
	if mount.mountPath == "/" && len(children) > 0 {
		err := mount.provider.Access(mount.relativePath, mode)
		if err != nil {
			if isNoEntryError(err) {
				return nil
			}
			return err
		}
		return nil
	}
	return mount.provider.Access(mount.relativePath, mode)
}

func (r *MountRouterProvider) Truncate(entryPath string, size int64) error {
	m, err := r.requireMount(entryPath, "truncate")
	if err != nil {
		return err
	}
	return m.provider.Truncate(m.relativePath, size)
}

func (r *MountRouterProvider) Close() error {
	for _, p := range r.mountMap {
		_ = p.Close()
	}
	return nil
}

// ---- helpers ----

type resolvedMount struct {
	mountPath    string
	provider     VirtualProvider
	relativePath string
}

func (r *MountRouterProvider) resolveMount(entryPath string) *resolvedMount {
	normalized := NormalizeVfsPath(entryPath)
	for _, mp := range r.mountPaths {
		if isUnderMountPoint(normalized, mp) {
			p := r.mountMap[mp]
			return &resolvedMount{mountPath: mp, provider: p, relativePath: getRelativePath(normalized, mp)}
		}
	}
	return nil
}

func (r *MountRouterProvider) requireMount(entryPath string, op string) (*resolvedMount, error) {
	m := r.resolveMount(entryPath)
	if m == nil {
		// If this is a virtual directory, treat open/mkdir/etc as ENOENT like TS.
		return nil, CreateErrnoError(int(syscall.ENOENT), op, entryPath)
	}
	return m, nil
}

func (r *MountRouterProvider) virtualChildren(entryPath string) []string {
	normalized := NormalizeVfsPath(entryPath)
	prefix := normalized
	if prefix != "/" {
		prefix += "/"
	}

	set := map[string]struct{}{}
	for _, mp := range r.mountPaths {
		if mp == normalized {
			continue
		}
		if !strings.HasPrefix(mp, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(mp, prefix)
		seg := strings.SplitN(remainder, "/", 2)[0]
		if seg != "" {
			set[seg] = struct{}{}
		}
	}

	children := make([]string, 0, len(set))
	for k := range set {
		children = append(children, k)
	}
	sort.Strings(children)
	return children
}

func isNoEntryError(err error) bool {
	var ee *ErrnoError
	if errors.As(err, &ee) {
		return ee.Errno == int(syscall.ENOENT)
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		if errno, ok := pe.Err.(syscall.Errno); ok {
			return errno == syscall.ENOENT
		}
	}
	return false
}

func isUnderMountPoint(normalizedPath string, mountPoint string) bool {
	if normalizedPath == mountPoint {
		return true
	}
	if mountPoint == "/" {
		return strings.HasPrefix(normalizedPath, "/")
	}
	return strings.HasPrefix(normalizedPath, mountPoint+"/")
}

func getRelativePath(normalizedPath string, mountPoint string) string {
	if normalizedPath == mountPoint {
		return "/"
	}
	if mountPoint == "/" {
		return normalizedPath
	}
	rel := strings.TrimPrefix(normalizedPath, mountPoint)
	if rel == "" {
		return "/"
	}
	return rel
}

func createVirtualDirStats() Stats {
	now := nowMs()
	return Stats{Mode: S_IFDIR | 0o755, Nlink: 1, UID: 0, GID: 0, Size: 4096, AtimeMs: now, MtimeMs: now, CtimeMs: now}
}

func formatVirtualEntries(entries []string) []Dirent {
	out := make([]Dirent, 0, len(entries))
	for _, e := range entries {
		out = append(out, Dirent{Name: e, Type: DirentDir})
	}
	return out
}

func mergeEntries(entries []Dirent, children []string) []Dirent {
	if len(children) == 0 {
		return entries
	}
	childSet := map[string]struct{}{}
	for _, c := range children {
		childSet[c] = struct{}{}
	}
	out := make([]Dirent, 0, len(entries)+len(children))
	for _, e := range entries {
		if _, ok := childSet[e.Name]; ok {
			continue
		}
		out = append(out, e)
	}
	for _, c := range children {
		out = append(out, Dirent{Name: c, Type: DirentDir})
	}
	return out
}
