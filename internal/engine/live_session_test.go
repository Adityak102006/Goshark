package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"goshark/internal/capturefile"
	"goshark/internal/ipc"
)

func TestLivePacketBufferIsBoundedAndCopiesData(t *testing.T) {
	server := &Server{}
	defer server.Close()
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	packet := capturefile.Packet{Data: []byte{1}, Timestamp: time.Unix(1, 0), Original: 1}
	if err := server.storeLivePacket(captureID, 1, packet); err != nil {
		t.Fatal(err)
	}
	packet.Data[0] = 9
	first, err := server.livePacket(captureID, 1)
	if err != nil || first.Data[0] != 1 {
		t.Fatalf("stored packet was not copied: packet=%#v error=%v", first, err)
	}
	for number := uint64(2); number <= maxLiveSessionPackets+1; number++ {
		if err := server.storeLivePacket(captureID, number, capturefile.Packet{Data: []byte{1}, Timestamp: time.Unix(int64(number), 0), Original: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.finishLiveSession(captureID); err != nil {
		t.Fatal(err)
	}
	if _, err := server.livePacket(captureID, 1); err == nil {
		t.Fatal("oldest packet remained after the live packet-count limit")
	}
	if _, err := server.livePacket(captureID, maxLiveSessionPackets+1); err != nil {
		t.Fatalf("newest packet was not retained: %v", err)
	}
	snapshotPath, cleanup, truncated, err := server.snapshotLiveCapture(context.Background(), captureID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if truncated {
		t.Fatal("small live capture spool unexpectedly reported truncation")
	}
	reader, err := capturefile.OpenFile(snapshotPath, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var recorded uint64
	for {
		if _, err := reader.ReadPacket(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		recorded++
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if recorded != maxLiveSessionPackets+1 {
		t.Fatalf("spool recorded %d packets, want %d", recorded, maxLiveSessionPackets+1)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, cleanupCanceledSnapshot, _, err := server.snapshotLiveCapture(canceled, captureID); err == nil {
		cleanupCanceledSnapshot()
		t.Fatal("canceled live snapshot unexpectedly succeeded")
	}
}

func TestLiveSpoolMarksLimitAndReportsWriteFailures(t *testing.T) {
	server := &Server{}
	defer server.Close()
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	packet := capturefile.Packet{Data: []byte{1}, Timestamp: time.Unix(1, 0), Original: 1}
	if err := server.storeLivePacket(captureID, 1, packet); err != nil {
		t.Fatal(err)
	}
	server.sessionMu.RLock()
	session := server.sessions[captureID]
	server.sessionMu.RUnlock()
	session.spoolMu.Lock()
	session.spoolSize = maxLiveCaptureSpoolBytes - 16
	session.spoolMu.Unlock()
	if err := server.storeLivePacket(captureID, 2, packet); err != nil {
		t.Fatal(err)
	}
	session.spoolMu.Lock()
	truncated := session.spoolTruncated
	session.spoolMu.Unlock()
	if !truncated {
		t.Fatal("spool limit did not mark the live recording truncated")
	}
	if err := server.finishLiveSession(captureID); err != nil {
		t.Fatal(err)
	}

	failedServer := &Server{}
	defer failedServer.Close()
	failedID, err := failedServer.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	badPacket := capturefile.Packet{Data: []byte{1}, Timestamp: time.Unix(-1, 0), Original: 1}
	if err := failedServer.storeLivePacket(failedID, 1, badPacket); err == nil {
		t.Fatal("invalid packet timestamp did not fail spool write")
	}
	if err := failedServer.finishLiveSession(failedID); err == nil {
		t.Fatal("spool write failure was not propagated on session finish")
	}
	if _, _, _, err := failedServer.snapshotLiveCapture(context.Background(), failedID); err == nil {
		t.Fatal("spool write failure was not propagated to snapshot")
	}
}

func TestLiveSessionEvictionRemovesOldSpool(t *testing.T) {
	server := &Server{}
	defer server.Close()
	var firstID string
	var firstDirectory string
	for index := 0; index < maxLiveSessions+1; index++ {
		captureID, err := server.createLiveSession()
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			firstID = captureID
			server.sessionMu.RLock()
			firstDirectory = server.sessions[captureID].spoolDir
			server.sessionMu.RUnlock()
		}
	}
	if _, err := server.livePacket(firstID, 1); err == nil {
		t.Fatal("evicted live session remained available")
	}
	if _, err := os.Stat(firstDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evicted spool directory remains: %v", err)
	}
}

func TestLiveSessionCleanupRemovesPrivateSpool(t *testing.T) {
	server := &Server{}
	captureID, err := server.createLiveSession()
	if err != nil {
		t.Fatal(err)
	}
	server.sessionMu.RLock()
	directory := server.sessions[captureID].spoolDir
	server.sessionMu.RUnlock()
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("private spool directory not created: info=%v error=%v", info, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private spool directory remains after cleanup: %v", err)
	}
}

func TestLivePacketDetailAndByteRange(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/http.pcap", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacketInto(nil)
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
	if err := server.storeLivePacket(captureID, 7, packet); err != nil {
		t.Fatal(err)
	}
	detail := invoke(t, server, ipc.Message{ID: 31, Type: "request", Operation: "packet_detail", CaptureID: captureID, PacketNumber: 7})
	if detail.Type != "response" || detail.TotalBytes != uint32(len(packet.Data)) {
		t.Fatalf("live packet detail = %#v", detail)
	}
	foundHTTP := false
	for _, protocol := range detail.Protocols {
		if protocol.Name == "HTTP" {
			foundHTTP = true
		}
	}
	if !foundHTTP {
		t.Fatal("live packet details did not contain the recognized HTTP layer")
	}
	bytes := invoke(t, server, ipc.Message{
		ID: 32, Type: "request", Operation: "packet_bytes", CaptureID: captureID, PacketNumber: 7, ByteLength: 14,
	})
	if bytes.Type != "response" || bytes.TotalBytes != uint32(len(packet.Data)) || len(bytes.Data) != 14 {
		t.Fatalf("live packet bytes = %#v", bytes)
	}
	if _, err := server.livePacket(captureID, 8); err == nil {
		t.Fatal("missing live packet did not report expiration")
	}
}
