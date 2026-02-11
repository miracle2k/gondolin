package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const manifestFilename = "manifest.json"

// GuestAssets are the resolved guest image asset paths.
type GuestAssets struct {
	KernelPath string
	InitrdPath string
	RootfsPath string
}

type assetManifest struct {
	Version int `json:"version"`
	Assets  struct {
		Kernel    string `json:"kernel"`
		Initramfs string `json:"initramfs"`
		Rootfs    string `json:"rootfs"`
	} `json:"assets"`
}

// LoadGuestAssets resolves kernel/initrd/rootfs paths from an asset directory.
//
// It supports either a manifest.json (preferred) or the legacy default filenames:
// - vmlinuz-virt
// - initramfs.cpio.lz4
// - rootfs.ext4
func LoadGuestAssets(assetDir string) (GuestAssets, error) {
	if assetDir == "" {
		return GuestAssets{}, errors.New("assetDir is required")
	}
	resolved := assetDir
	if !filepath.IsAbs(resolved) {
		abs, err := filepath.Abs(resolved)
		if err == nil {
			resolved = abs
		}
	}

	kernelFile := "vmlinuz-virt"
	initrdFile := "initramfs.cpio.lz4"
	rootfsFile := "rootfs.ext4"

	manifestPath := filepath.Join(resolved, manifestFilename)
	if raw, err := os.ReadFile(manifestPath); err == nil {
		var m assetManifest
		if err := json.Unmarshal(raw, &m); err == nil && m.Version == 1 {
			if m.Assets.Kernel != "" {
				kernelFile = m.Assets.Kernel
			}
			if m.Assets.Initramfs != "" {
				initrdFile = m.Assets.Initramfs
			}
			if m.Assets.Rootfs != "" {
				rootfsFile = m.Assets.Rootfs
			}
		}
	}

	kernelPath := filepath.Join(resolved, kernelFile)
	initrdPath := filepath.Join(resolved, initrdFile)
	rootfsPath := filepath.Join(resolved, rootfsFile)

	missing := []string{}
	if _, err := os.Stat(kernelPath); err != nil {
		missing = append(missing, kernelFile)
	}
	if _, err := os.Stat(initrdPath); err != nil {
		missing = append(missing, initrdFile)
	}
	if _, err := os.Stat(rootfsPath); err != nil {
		missing = append(missing, rootfsFile)
	}
	if len(missing) > 0 {
		return GuestAssets{}, fmt.Errorf("missing guest assets in %s: %v", resolved, missing)
	}

	return GuestAssets{KernelPath: kernelPath, InitrdPath: initrdPath, RootfsPath: rootfsPath}, nil
}
