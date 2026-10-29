package dissection

import (
	"io"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"goshark/internal/capturefile"
)

func TestRealWirelessCaptureHasValidByteRanges(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/wep.pcapng.gz", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	foundInformationElement := false
	for number := 1; number <= 3; number++ {
		packet, err := reader.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if packet.LinkType != layers.LinkType(127) {
			t.Fatalf("wireless packet link type = %s", packet.LinkType)
		}
		result, err := Dissect(packet.Data, packet.LinkType)
		if err != nil {
			t.Fatalf("dissect packet %d: %v", number, err)
		}
		for _, protocol := range result.Protocols {
			if protocol.Start < 0 || protocol.Start > len(packet.Data) || protocol.Length < 0 || protocol.Length > len(packet.Data)-protocol.Start {
				t.Fatalf("packet %d has invalid protocol range: %#v", number, protocol)
			}
			if protocol.Name == "Dot11InformationElement" {
				foundInformationElement = true
			}
			for _, field := range protocol.Fields {
				if field.Bytes.Start < 0 || field.Bytes.Start > len(packet.Data) || field.Bytes.Length < 0 || field.Bytes.Length > len(packet.Data)-field.Bytes.Start {
					t.Fatalf("packet %d has invalid field range: %#v", number, field)
				}
			}
		}
	}
	if !foundInformationElement {
		t.Fatal("wireless beacon did not include its information element layers")
	}
}
