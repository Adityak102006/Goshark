package capturefile

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestPCAPWriterProducesReadableCapture(t *testing.T) {
	var encoded bytes.Buffer
	if err := WritePCAPHeader(&encoded, 4096, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	want := Packet{
		Data:      []byte{1, 2, 3, 4},
		Timestamp: time.Unix(1700000000, 123456789),
		Original:  7,
		LinkType:  layers.LinkTypeEthernet,
	}
	if err := WritePCAPPacket(&encoded, want, 4096); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(io.NopCloser(bytes.NewReader(encoded.Bytes())), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, want.Data) || got.Original != want.Original || got.LinkType != want.LinkType || !got.Timestamp.Equal(time.Unix(1700000000, 123456000)) {
		t.Fatalf("decoded packet = %#v", got)
	}
}

func TestPCAPWriterRejectsInvalidLengthsAndTimestamps(t *testing.T) {
	var encoded bytes.Buffer
	invalid := []Packet{
		{Data: []byte{1}, Original: 0, Timestamp: time.Unix(-1, 0)},
		{Data: []byte{1, 2}, Original: 1, Timestamp: time.Unix(0, 0)},
	}
	for _, packet := range invalid {
		if err := WritePCAPPacket(&encoded, packet, 4096); err == nil {
			t.Fatalf("invalid packet was written: %#v", packet)
		}
	}
}
