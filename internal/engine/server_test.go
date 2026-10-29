package engine

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"goshark/internal/ipc"
)

func TestOpenCaptureStreamsRowsAndEnd(t *testing.T) {
	server := &Server{}
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	request := ipc.Message{ID: 1, Type: "request", Operation: "open_capture", Path: "../../testdata/http.pcap", DisplayFilter: "tcp.port == 80"}
	result := make(chan error, 1)
	go func() {
		result <- server.Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	first, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if first.Type != "response" || first.Format != "pcap" {
		t.Fatalf("initial message = %#v", first)
	}
	batch, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Type != "batch" || len(batch.Frames) != 1 || batch.Frames[0].Protocol != "HTTP" {
		t.Fatalf("packet batch = %#v", batch)
	}
	if batch.Frames[0].SourcePort == "" || batch.Frames[0].DestinationPort != "80" || !strings.HasPrefix(batch.Frames[0].Info, "HTTP HEAD ") {
		t.Fatalf("packet summary fields = %#v", batch.Frames[0])
	}
	end, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if end.Type != "end" || end.Captured != 1 || end.Displayed != 1 {
		t.Fatalf("end message = %#v", end)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestOpenCaptureLimitCountsFilteredPackets(t *testing.T) {
	server := &Server{}
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	request := ipc.Message{
		ID: 2, Type: "request", Operation: "open_capture", Path: "../../testdata/http.pcap", DisplayFilter: "tcp.port == 443", Limit: 1,
	}
	result := make(chan error, 1)
	go func() {
		result <- server.Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	if _, err := ipc.ReadMessage(clientSide); err != nil {
		t.Fatal(err)
	}
	end, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if end.Type != "end" || end.Captured != 1 || end.Displayed != 0 {
		t.Fatalf("end message = %#v", end)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestLocalIPCStreamsCapture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain socket integration is platform-specific")
	}
	path := filepath.Join(t.TempDir(), "goshark", "engine.sock")
	listener, err := ipc.ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- ipc.Serve(ctx, listener, (&Server{}).Handle)
	}()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteMessage(connection, ipc.Message{
		ID: 8, Type: "request", Operation: "open_capture", Path: "../../testdata/http.pcap", DisplayFilter: "tcp.port == 80",
	}); err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{"response", "batch", "end"}
	for _, want := range wantTypes {
		message, err := ipc.ReadMessage(connection)
		if err != nil {
			t.Fatal(err)
		}
		if message.Type != want || message.ID != 8 {
			t.Fatalf("message = %#v, want type %q and id 8", message, want)
		}
	}
	cancel()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPC server did not stop after cancellation")
	}
}

func TestPacketDetailAndByteRange(t *testing.T) {
	server := &Server{}
	request := ipc.Message{ID: 4, Type: "request", Operation: "packet_detail", Path: "../../testdata/http.pcap", PacketNumber: 1}
	message := invoke(t, server, request)
	if message.Type != "response" || message.TotalBytes != 207 || len(message.Protocols) == 0 {
		t.Fatalf("detail response = %#v", message)
	}
	foundTCPPort := false
	for _, protocol := range message.Protocols {
		if protocol.Name != "TCP" {
			continue
		}
		for _, field := range protocol.Fields {
			if field.Name == "Destination port" && field.ByteStart == 36 && field.ByteLength == 2 {
				foundTCPPort = true
			}
		}
	}
	if !foundTCPPort {
		t.Fatal("TCP port field byte range was not returned")
	}
	byteMessage := invoke(t, server, ipc.Message{
		ID: 5, Type: "request", Operation: "packet_bytes", Path: "../../testdata/http.pcap", PacketNumber: 1, ByteOffset: 0, ByteLength: 14,
	})
	if len(byteMessage.Data) != 14 || byteMessage.TotalBytes != 207 || byteMessage.More != true {
		t.Fatalf("packet byte response = %#v", byteMessage)
	}
}

func invoke(t *testing.T, server *Server, request ipc.Message) ipc.Message {
	t.Helper()
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	result := make(chan error, 1)
	go func() {
		result <- server.Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	message, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return message
}
