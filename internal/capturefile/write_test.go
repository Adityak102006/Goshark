package capturefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicFileCommit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "capture.pcap")
	output, err := NewAtomicFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if _, err := output.File().Write([]byte("capture")); err != nil {
		t.Fatal(err)
	}
	if err := output.Commit(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "capture" {
		t.Fatalf("output = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
	}
}

func TestAtomicFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, err := NewAtomicFile(link); err == nil {
		t.Fatal("symbolic link output path was accepted")
	}
}
