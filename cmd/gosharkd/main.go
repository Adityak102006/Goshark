package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"goshark/internal/engine"
	"goshark/internal/ipc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(arguments []string) (runErr error) {
	flags := flag.NewFlagSet("gosharkd", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}
	flags.StringVar(&socketPath, "socket", socketPath, "local IPC socket path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	listener, err := ipc.ListenLocal(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := listener.Close()
		if !errors.Is(closeErr, net.ErrClosed) {
			runErr = errors.Join(runErr, closeErr)
		}
	}()
	fmt.Fprintf(os.Stderr, "goshark engine listening on local IPC socket\n")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	server := &engine.Server{}
	defer func() {
		runErr = errors.Join(runErr, server.Close())
	}()
	return ipc.Serve(ctx, listener, server.Handle)
}
