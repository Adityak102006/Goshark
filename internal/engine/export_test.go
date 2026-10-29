package engine

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"goshark/internal/capturefile"
	"goshark/internal/ipc"
)

func TestExportOfflineCaptureToPCAP(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "export.pcap")
	message := invoke(t, &Server{}, ipc.Message{
		ID: 41, Type: "request", Operation: "save_capture", Path: "../../testdata/http.pcap", OutputPath: outputPath, DisplayFilter: "tcp.port == 80",
	})
	if message.Type != "response" || message.Format != "pcap" || message.Captured != 1 || message.Displayed != 1 {
		t.Fatalf("export response = %#v", message)
	}
	reader, err := capturefile.OpenFile(outputPath, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if len(packet.Data) != 207 || packet.LinkType.String() != "Ethernet" {
		t.Fatalf("exported packet = %#v", packet)
	}
}

func TestExportCompressedPCAPNGToPCAP(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "wireless-export.pcap")
	message := invoke(t, &Server{}, ipc.Message{
		ID: 44, Type: "request", Operation: "save_capture", Path: "../../testdata/wep.pcapng.gz", OutputPath: outputPath,
	})
	if message.Type != "response" || message.Format != "pcap" || message.Displayed == 0 {
		t.Fatalf("compressed PCAPNG export response = %#v", message)
	}
	reader, err := capturefile.OpenFile(outputPath, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if reader.Format() != capturefile.FormatPCAP {
		reader.Close()
		t.Fatalf("export format = %v, want classic PCAP", reader.Format())
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if packet.LinkType != 127 {
		t.Fatalf("exported wireless link type = %s", packet.LinkType)
	}
}

func TestExportLiveCaptureSnapshot(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/http.pcap", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	defer server.Close()
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.storeLivePacket(captureID, 3, packet); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "live-export.pcap")
	engineSide, clientSide := net.Pipe()
	if err := server.saveCapture(context.Background(), ipc.Message{
		ID: 42, Type: "request", Operation: "save_capture", CaptureID: captureID, OutputPath: outputPath, DisplayFilter: "tcp.port == 80",
	}, engineSide); err == nil {
		engineSide.Close()
		clientSide.Close()
		t.Fatal("live capture was exportable before it stopped")
	}
	engineSide.Close()
	clientSide.Close()
	if err := server.finishLiveSession(captureID); err != nil {
		t.Fatal(err)
	}
	message := invoke(t, server, ipc.Message{
		ID: 42, Type: "request", Operation: "save_capture", CaptureID: captureID, OutputPath: outputPath, DisplayFilter: "tcp.port == 80",
	})
	if message.Type != "response" || message.Displayed != 1 {
		t.Fatalf("live export response = %#v", message)
	}
	if _, err := capturefile.OpenFile(outputPath, capturefile.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestLiveExportReportsSpoolTruncation(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/http.pcap", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	defer server.Close()
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.storeLivePacket(captureID, 1, packet); err != nil {
		t.Fatal(err)
	}
	server.sessionMu.RLock()
	session := server.sessions[captureID]
	server.sessionMu.RUnlock()
	session.spoolMu.Lock()
	session.spoolTruncated = true
	session.spoolMu.Unlock()
	if err := server.finishLiveSession(captureID); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "truncated-live-export.pcap")
	message := invoke(t, server, ipc.Message{
		ID: 45, Type: "request", Operation: "save_capture", CaptureID: captureID, OutputPath: outputPath, DisplayFilter: "tcp.port == 80",
	})
	if message.Type != "response" || !message.Truncated {
		t.Fatalf("truncated live export response = %#v", message)
	}
}

func TestLiveExportIncludesPacketsBeyondDetailCache(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/http.pcap", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	defer server.Close()
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	for number := uint64(1); number <= maxLiveSessionPackets+1; number++ {
		if err := server.storeLivePacket(captureID, number, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.finishLiveSession(captureID); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "complete-live-export.pcap")
	message := invoke(t, server, ipc.Message{
		ID: 44, Type: "request", Operation: "save_capture", CaptureID: captureID, OutputPath: outputPath, DisplayFilter: "tcp.port == 80",
	})
	if message.Type != "response" || message.Captured != maxLiveSessionPackets+1 || message.Displayed != maxLiveSessionPackets+1 {
		t.Fatalf("full live export response = %#v", message)
	}
}

func TestExportRejectsSameSourceAndDestination(t *testing.T) {
	engineSide, clientSide := net.Pipe()
	defer engineSide.Close()
	defer clientSide.Close()
	err := (&Server{}).saveCapture(context.Background(), ipc.Message{
		ID: 43, Type: "request", Operation: "save_capture", Path: "../../testdata/http.pcap", OutputPath: "../../testdata/http.pcap",
	}, engineSide)
	if err == nil {
		t.Fatal("same-source export was accepted")
	}
}
