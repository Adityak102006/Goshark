package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestListenLocalRestrictsDirectoryAndSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket permission modes are not available on Windows")
	}
	path := filepath.Join(t.TempDir(), "goshark", "engine.sock")
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for target, expected := range map[string]os.FileMode{
		filepath.Dir(path): 0o700,
		path:               0o600,
	} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("permissions for %q = %04o, want %04o", target, info.Mode().Perm(), expected)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path remains after Close: %v", err)
	}
}

func TestListenLocalRejectsSymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	linked := filepath.Join(root, "linked")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLocal(filepath.Join(linked, "engine.sock")); err == nil {
		t.Fatal("symlinked IPC directory was accepted")
	}
}

func TestListenLocalRejectsActiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket stale-path behavior is not available on Windows")
	}
	path := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := ListenLocal(path); err == nil {
		t.Fatal("second listener on active socket was accepted")
	}
}

func TestServeStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, listener, func(context.Context, Message, net.Conn) error { return nil })
	}()
	cancel()
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPC server did not stop after cancellation")
	}
}
