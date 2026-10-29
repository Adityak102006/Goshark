package ipc

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestRoundTripRequest(t *testing.T) {
	want := Message{ID: 7, Type: "request", Operation: "open_capture", Path: "/tmp/capture.pcapng", DisplayFilter: "tcp.port == 443"}
	var encoded bytes.Buffer
	if err := WriteMessage(&encoded, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Type != want.Type || got.Operation != want.Operation || got.Path != want.Path || got.DisplayFilter != want.DisplayFilter {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestRejectOversizedFrameBeforeAllocation(t *testing.T) {
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], MaxMessageBytes+1)
	if _, err := ReadMessage(bytes.NewReader(frame[:])); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestRejectUnknownJSONField(t *testing.T) {
	body := []byte(`{"id":1,"type":"request","operation":"list_interfaces","unsafe":true}`)
	var frame bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	frame.Write(header[:])
	frame.Write(body)
	if _, err := ReadMessage(&frame); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestRejectInvalidRequestSchema(t *testing.T) {
	tests := []Message{
		{Type: "request", Operation: "list_interfaces"},
		{ID: 1, Type: "request", Operation: "open_capture"},
		{ID: 1, Type: "request", Operation: "unsupported"},
		{ID: 1, Type: "request", Operation: "list_interfaces", Error: "forged response"},
		{ID: 1, Type: "request", Operation: "list_interfaces", Path: "bad\x00path"},
		{ID: 1, Type: "request", Operation: "start_capture", InterfaceName: "lo", DisplayFilter: strings.Repeat("x", MaxStringBytes+1)},
		{ID: 1, Type: "request", Operation: "packet_detail", PacketNumber: 1},
		{ID: 1, Type: "request", Operation: "packet_detail", CaptureID: strings.Repeat("x", 65), PacketNumber: 1},
		{ID: 1, Type: "request", Operation: "packet_detail", CaptureID: "valid", Path: "/tmp/other.pcap", PacketNumber: 1},
	}
	for index, message := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			if err := Validate(message); err == nil {
				t.Fatalf("Validate(%#v) succeeded", message)
			}
		})
	}
}

func TestRejectTrailingJSON(t *testing.T) {
	body := []byte(`{"id":1,"type":"request","operation":"list_interfaces"} {}`)
	var frame bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	frame.Write(header[:])
	frame.Write(body)
	if _, err := ReadMessage(&frame); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func FuzzReadMessage(f *testing.F) {
	var valid bytes.Buffer
	if err := WriteMessage(&valid, Message{ID: 1, Type: "request", Operation: "list_interfaces"}); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{0, 0, 0, 4, '{', '}', 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMessageBytes+4 {
			t.Skip()
		}
		_, _ = ReadMessage(bytes.NewReader(data))
	})
}
