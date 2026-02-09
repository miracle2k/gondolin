package vfs

import (
	"reflect"
	"syscall"
	"testing"
)

func TestNormalizeMountPathValidatesAndNormalizes(t *testing.T) {
	if _, err := NormalizeMountPath(""); err == nil {
		t.Fatalf("expected error for empty path")
	}
	if _, err := NormalizeMountPath("relative"); err == nil {
		t.Fatalf("expected error for relative path")
	}
	if _, err := NormalizeMountPath("/bad\x00path"); err == nil {
		t.Fatalf("expected error for null byte path")
	}
	p, err := NormalizeMountPath("/data/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != "/data" {
		t.Fatalf("expected /data, got %q", p)
	}
}

func TestNormalizeMountMapRejectsInvalidProvidersAndDuplicates(t *testing.T) {
	provider := NewMemoryProvider()
	if _, err := NormalizeMountMap(map[string]VirtualProvider{"/data": nil}); err == nil {
		t.Fatalf("expected error for nil provider")
	}
	if _, err := NormalizeMountMap(map[string]VirtualProvider{"/data": provider, "/data/": provider}); err == nil {
		t.Fatalf("expected duplicate mount path error")
	}
}

func TestListMountPathsSortsNormalizedEntries(t *testing.T) {
	provider := NewMemoryProvider()
	paths, err := ListMountPaths(map[string]VirtualProvider{"/b": provider, "/a/": provider})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	expected := []string{"/a", "/b"}
	if !reflect.DeepEqual(paths, expected) {
		t.Fatalf("expected %#v, got %#v", expected, paths)
	}
}

func TestMountRouterProviderMergesVirtualChildren(t *testing.T) {
	rootProvider := NewMemoryProvider()
	rootHandle, err := rootProvider.Open("/root.txt", "w+", 0)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	_ = rootHandle.WriteFile([]byte("root"))
	_ = rootHandle.Close()

	appProvider := NewMemoryProvider()
	appHandle, err := appProvider.Open("/info.txt", "w+", 0)
	if err != nil {
		t.Fatalf("open app: %v", err)
	}
	_ = appHandle.WriteFile([]byte("info"))
	_ = appHandle.Close()

	router, err := NewMountRouterProvider(map[string]VirtualProvider{"/": rootProvider, "/app": appProvider})
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	rootEntries, err := router.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir /: %v", err)
	}
	var hasRoot, hasApp bool
	for _, e := range rootEntries {
		switch e.Name {
		case "root.txt":
			hasRoot = true
		case "app":
			hasApp = true
		}
	}
	if !hasRoot || !hasApp {
		t.Fatalf("expected root.txt and app in / entries: %#v", rootEntries)
	}

	appStats, err := router.Stat("/app")
	if err != nil {
		t.Fatalf("stat /app: %v", err)
	}
	if !appStats.IsDirectory() {
		t.Fatalf("expected /app to be directory")
	}

	appEntries, err := router.ReadDir("/app")
	if err != nil {
		t.Fatalf("readdir /app: %v", err)
	}
	foundInfo := false
	for _, e := range appEntries {
		if e.Name == "info.txt" {
			foundInfo = true
			break
		}
	}
	if !foundInfo {
		t.Fatalf("expected info.txt in /app")
	}

	if err := router.Rename("/root.txt", "/app/other.txt"); err == nil || !isErrno(err, syscall.EXDEV) {
		t.Fatalf("expected EXDEV, got %v", err)
	}
}

func TestMountRouterProviderExposesVirtualRootWithoutBaseMount(t *testing.T) {
	dataProvider := NewMemoryProvider()
	router, err := NewMountRouterProvider(map[string]VirtualProvider{"/data": dataProvider})
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	rootEntries, err := router.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir /: %v", err)
	}
	names := make([]string, 0, len(rootEntries))
	for _, e := range rootEntries {
		names = append(names, e.Name)
	}
	if !reflect.DeepEqual(names, []string{"data"}) {
		t.Fatalf("expected [data], got %#v", names)
	}

	rootStats, err := router.Stat("/")
	if err != nil {
		t.Fatalf("stat /: %v", err)
	}
	if !rootStats.IsDirectory() {
		t.Fatalf("expected / to be directory")
	}

	if _, err := router.Open("/missing.txt", "r", 0); err == nil || !isErrno(err, syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
}

func TestMountRouterProviderResolvesDeepNestedMountsAndNormalizesTraversal(t *testing.T) {
	write := func(provider *MemoryProvider, pth string, contents string) {
		fh, err := provider.Open(pth, "w+", 0)
		if err != nil {
			t.Fatalf("open %s: %v", pth, err)
		}
		_ = fh.WriteFile([]byte(contents))
		_ = fh.Close()
	}

	root := NewMemoryProvider()
	a := NewMemoryProvider()
	b := NewMemoryProvider()
	c := NewMemoryProvider()

	write(root, "/root.txt", "root")
	write(a, "/id.txt", "A")
	write(b, "/id.txt", "B")
	write(c, "/id.txt", "C")

	router, err := NewMountRouterProvider(map[string]VirtualProvider{
		"/":      root,
		"/a":     a,
		"/a/b":   b,
		"/a/b/c": c,
	})
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	check := func(openPath string, expected string) {
		fh, err := router.Open(openPath, "r", 0)
		if err != nil {
			t.Fatalf("open %s: %v", openPath, err)
		}
		data, err := fh.ReadFile()
		if err != nil {
			t.Fatalf("readFile %s: %v", openPath, err)
		}
		_ = fh.Close()
		if string(data) != expected {
			t.Fatalf("%s: expected %q, got %q", openPath, expected, string(data))
		}
	}

	check("/a/b/c/id.txt", "C")
	check("/a/b/id.txt", "B")
	check("/a/id.txt", "A")

	stA, err := router.Stat("/a")
	if err != nil {
		t.Fatalf("stat /a: %v", err)
	}
	if !stA.IsDirectory() {
		t.Fatalf("expected /a virtual dir")
	}
	stB, err := router.Stat("/a/b")
	if err != nil {
		t.Fatalf("stat /a/b: %v", err)
	}
	if !stB.IsDirectory() {
		t.Fatalf("expected /a/b virtual dir")
	}

	check("/a/b/c/../id.txt", "B")
	check("/a/../root.txt", "root")
}

func TestMountRouterProviderVirtualChildMasksConflictingBaseEntry(t *testing.T) {
	rootProvider := NewMemoryProvider()
	rootApp, err := rootProvider.Open("/app", "w+", 0)
	if err != nil {
		t.Fatalf("open /app: %v", err)
	}
	_ = rootApp.WriteFile([]byte("this is a file named app"))
	_ = rootApp.Close()

	appProvider := NewMemoryProvider()
	appFile, err := appProvider.Open("/info.txt", "w+", 0)
	if err != nil {
		t.Fatalf("open /info: %v", err)
	}
	_ = appFile.WriteFile([]byte("info"))
	_ = appFile.Close()

	router, err := NewMountRouterProvider(map[string]VirtualProvider{"/": rootProvider, "/app": appProvider})
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	entries, err := router.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir /: %v", err)
	}
	var app *Dirent
	for i := range entries {
		if entries[i].Name == "app" {
			app = &entries[i]
			break
		}
	}
	if app == nil {
		t.Fatalf("expected app entry")
	}
	if !app.IsDirectory() {
		t.Fatalf("expected app to be directory, got type=%v", app.Type)
	}
}
