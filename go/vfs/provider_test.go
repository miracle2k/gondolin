package vfs

import (
	"reflect"
	"testing"
)

func TestSandboxVfsProviderHooksWrapHandleOperations(t *testing.T) {
	provider := NewMemoryProvider()
	events := make([]string, 0)

	vfs := NewSandboxVfsProvider(provider, Hooks{
		Before: func(ctx *HookContext) error {
			events = append(events, "before:"+ctx.Op)
			return nil
		},
		After: func(ctx *HookContext) error {
			events = append(events, "after:"+ctx.Op)
			return nil
		},
	})

	h, err := vfs.Open("/file.txt", "w+", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := h.WriteFile([]byte("hello")); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	expected := []string{
		"before:open",
		"after:open",
		"before:writeFile",
		"after:writeFile",
		"before:release",
		"after:release",
	}
	if !reflect.DeepEqual(events, expected) {
		t.Fatalf("events mismatch\nexpected: %#v\nactual:   %#v", expected, events)
	}
}
