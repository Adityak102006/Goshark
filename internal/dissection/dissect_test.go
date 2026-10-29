package dissection

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"goshark/internal/capturefile"
)

func TestRealCaptureProvidesSelectableFieldRanges(t *testing.T) {
	input, err := os.Open("../../testdata/http.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, err := capturefile.NewReader(input, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	foundTCP := false
	foundTCPFlags := false
	foundHTTP := false
	for {
		packet, err := reader.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		result, err := Dissect(packet.Data, packet.LinkType)
		if err != nil {
			t.Fatal(err)
		}
		for _, protocol := range result.Protocols {
			if protocol.Name == "HTTP" {
				for _, field := range protocol.Fields {
					if field.Name == "Method" && field.Value == "HEAD" && field.Bytes.Start >= 0 && field.Bytes.Start+field.Bytes.Length <= len(packet.Data) {
						foundHTTP = true
					}
				}
			}
			if protocol.Name != "TCP" {
				continue
			}
			for _, field := range protocol.Fields {
				if field.Name == "Flags" && field.Value != "" && field.Bytes.Length == 1 {
					foundTCPFlags = true
				}
				if field.Name == "Source port" {
					if field.Bytes.Start < 0 || field.Bytes.Length != 2 || field.Bytes.Start+field.Bytes.Length > len(packet.Data) {
						t.Fatalf("invalid selectable byte range: %+v", field.Bytes)
					}
					foundTCP = true
				}
			}
		}
	}
	if !foundTCP {
		t.Fatal("real HTTP capture did not produce a selectable TCP field")
	}
	if !foundTCPFlags {
		t.Fatal("real HTTP capture did not produce TCP flag details")
	}
	if !foundHTTP {
		t.Fatal("real HTTP capture did not produce HTTP request details")
	}
}

func TestMalformedPacketReturnsResultWithoutPanic(t *testing.T) {
	result, err := Dissect([]byte{0xff, 0x00, 0x10}, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("Dissect returned fatal error: %v", err)
	}
	if len(result.Protocols) == 0 && result.Error == "" {
		t.Fatal("malformed packet has neither protocol details nor a decode error")
	}
}

func FuzzDissect(f *testing.F) {
	for _, fixture := range []string{"../../testdata/arp.pcap", "../../testdata/http.pcap"} {
		input, err := os.Open(fixture)
		if err != nil {
			f.Fatal(err)
		}
		reader, err := capturefile.NewReader(input, capturefile.DefaultLimits())
		if err != nil {
			input.Close()
			f.Fatal(err)
		}
		packet, err := reader.ReadPacket()
		if err != nil {
			input.Close()
			f.Fatal(err)
		}
		f.Add(packet.Data, uint16(packet.LinkType))
		input.Close()
	}
	f.Fuzz(func(t *testing.T, data []byte, linkType uint16) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		result, err := Dissect(data, layers.LinkType(linkType))
		if err != nil {
			return
		}
		for _, protocol := range result.Protocols {
			if protocol.Start < 0 || protocol.Length < 0 || protocol.Start > len(data) || protocol.Length > len(data)-protocol.Start {
				t.Fatalf("invalid protocol range: %+v packet length=%d", protocol, len(data))
			}
			for _, field := range protocol.Fields {
				if field.Bytes.Start < 0 || field.Bytes.Length < 0 || field.Bytes.Start > len(data) || field.Bytes.Length > len(data)-field.Bytes.Start {
					t.Fatalf("invalid field range: %+v packet length=%d", field, len(data))
				}
			}
		}
	})
}
