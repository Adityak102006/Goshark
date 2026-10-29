package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type RequestHandler func(context.Context, Message, net.Conn) error

type localSocketListener struct {
	net.Listener
	path      string
	closeOnce sync.Once
	closeErr  error
}

func (listener *localSocketListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closeErr = listener.Listener.Close()
		if err := os.Remove(listener.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			listener.closeErr = errors.Join(listener.closeErr, err)
		}
	})
	return listener.closeErr
}

func DefaultSocketPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user configuration directory: %w", err)
	}
	return filepath.Join(directory, "goshark", "engine.sock"), nil
}

func ListenLocal(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("IPC socket path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve IPC socket path: %w", err)
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create IPC directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect IPC directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, errors.New("IPC directory must be a real directory, not a symbolic link")
	}
	if runtime.GOOS != "windows" {
		// #nosec G302 -- owner-only directory permissions isolate the local IPC socket.
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("restrict IPC directory permissions: %w", err)
		}
	}
	name := filepath.Join(directory, filepath.Base(absolute))
	if info, err := os.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("IPC socket path must not be a symbolic link")
		}
		if runtime.GOOS == "windows" || info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("IPC path already exists and is not a stale Unix socket")
		}
		connection, dialErr := net.DialTimeout("unix", name, 100*time.Millisecond)
		if dialErr == nil {
			if closeErr := connection.Close(); closeErr != nil {
				return nil, fmt.Errorf("close IPC socket probe: %w", closeErr)
			}
			return nil, errors.New("goshark engine is already listening on the IPC socket")
		}
		if err := os.Remove(name); err != nil {
			return nil, fmt.Errorf("remove stale IPC socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect IPC socket path: %w", err)
	}
	listener, err := net.Listen("unix", name)
	if err != nil {
		return nil, fmt.Errorf("listen on local IPC socket: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(name, 0o600); err != nil {
			closeErr := listener.Close()
			removeErr := os.Remove(name)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
			return nil, errors.Join(fmt.Errorf("restrict IPC socket permissions: %w", err), closeErr, removeErr)
		}
	}
	return &localSocketListener{Listener: listener, path: name}, nil
}

func Serve(ctx context.Context, listener net.Listener, handler RequestHandler) error {
	if ctx == nil || listener == nil || handler == nil {
		return errors.New("IPC server requires a context, listener, and handler")
	}
	var workers sync.WaitGroup
	serverDone := make(chan struct{})
	listenerClose := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			listenerClose <- listener.Close()
		case <-serverDone:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				closeErr := <-listenerClose
				if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					close(serverDone)
					workers.Wait()
					return fmt.Errorf("close IPC listener: %w", closeErr)
				}
				break
			}
			close(serverDone)
			workers.Wait()
			return fmt.Errorf("accept IPC connection: %w", err)
		}
		workers.Add(1)
		go func(connection net.Conn) {
			defer workers.Done()
			defer connection.Close()
			if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return
			}
			request, err := ReadMessage(connection)
			if err != nil {
				return
			}
			if err := connection.SetReadDeadline(time.Time{}); err != nil {
				return
			}
			if err := handler(ctx, request, connection); err != nil {
				if writeErr := WriteMessage(connection, Message{ID: request.ID, Type: "error", Error: safeMessage(err.Error())}); writeErr != nil {
					return
				}
			}
		}(connection)
	}
	close(serverDone)
	workers.Wait()
	return nil
}

func safeMessage(value string) string {
	if len(value) > MaxStringBytes {
		value = value[:MaxStringBytes]
	}
	output := make([]byte, 0, len(value))
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			output = append(output, '?')
		} else {
			output = append(output, string(character)...)
		}
	}
	return string(output)
}
