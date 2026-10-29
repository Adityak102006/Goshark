package capturefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type AtomicFile struct {
	root        *os.Root
	file        *os.File
	temporary   string
	destination string
	committed   bool
}

func NewAtomicFile(path string) (*AtomicFile, error) {
	if path == "" {
		return nil, errors.New("output path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("canonicalize output directory: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open output directory: %w", err)
	}
	destination := filepath.Base(absolute)
	info, err := root.Lstat(destination)
	if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.Join(errors.New("output path must be a regular file and not a symbolic link"), root.Close())
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(fmt.Errorf("inspect output path: %w", err), root.Close())
	}
	for attempt := 0; attempt < 8; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, errors.Join(fmt.Errorf("generate temporary output name: %w", err), root.Close())
		}
		temporary := ".goshark-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("create temporary output: %w", err), root.Close())
		}
		return &AtomicFile{
			root:        root,
			file:        file,
			temporary:   temporary,
			destination: destination,
		}, nil
	}
	return nil, errors.Join(errors.New("could not allocate a unique temporary output file"), root.Close())
}

func (f *AtomicFile) File() *os.File {
	return f.file
}

func (f *AtomicFile) Commit() error {
	if f == nil || f.file == nil || f.committed {
		return errors.New("atomic output is not open")
	}
	if err := f.file.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := f.file.Close(); err != nil {
		f.file = nil
		return fmt.Errorf("close temporary output: %w", err)
	}
	f.file = nil
	if err := f.root.Rename(f.temporary, f.destination); err != nil {
		return fmt.Errorf("commit output file: %w", err)
	}
	f.committed = true
	return nil
}

func (f *AtomicFile) Close() error {
	if f == nil {
		return nil
	}
	var closeErr error
	if f.file != nil {
		closeErr = f.file.Close()
		f.file = nil
	}
	if !f.committed && f.root != nil {
		closeErr = errors.Join(closeErr, f.root.Remove(f.temporary))
	}
	if f.root != nil {
		closeErr = errors.Join(closeErr, f.root.Close())
		f.root = nil
	}
	return closeErr
}
