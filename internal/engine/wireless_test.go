package engine

import (
	"context"
	"net"
	"testing"

	"goshark/internal/ipc"
)

func TestOpenWirelessCaptureUsesBeaconSummary(t *testing.T) {
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	request := ipc.Message{ID: 51, Type: "request", Operation: "open_capture", Path: "../../testdata/wep.pcapng.gz", Limit: 1}
	result := make(chan error, 1)
	go func() {
		result <- (&Server{}).Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	if _, err := ipc.ReadMessage(clientSide); err != nil {
		t.Fatal(err)
	}
	batch, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Type != "batch" || len(batch.Frames) != 1 || batch.Frames[0].Protocol != "Dot11MgmtBeacon" || batch.Frames[0].Info != "802.11 MgmtBeacon" {
		t.Fatalf("wireless packet summary = %#v", batch)
	}
	end, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if end.Type != "end" {
		t.Fatalf("wireless capture end = %#v", end)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
