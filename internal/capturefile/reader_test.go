package capturefile

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func TestOpenCanonicalCapturePath(t *testing.T) {
	reader, err := OpenFile("../../testdata/arp.pcap", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectSymbolicLinkCapturePath(t *testing.T) {
	link := t.TempDir() + "/capture.pcap"
	if err := os.Symlink("../../testdata/arp.pcap", link); err != nil {
		t.Skip(err)
	}
	if _, err := OpenFile(link, DefaultLimits()); err == nil {
		t.Fatal("symbolic link capture path was accepted")
	}
}

func TestRealPCAPFixture(t *testing.T) {
	input, err := os.Open("../../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	reader, err := NewReader(input, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if reader.Format() != FormatPCAP {
		t.Fatalf("format = %v, want pcap", reader.Format())
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Data) != 30 || packet.Original != 30 || uint16(packet.LinkType) != 107 {
		t.Fatalf("unexpected packet metadata: captured=%d original=%d link=%d", len(packet.Data), packet.Original, packet.LinkType)
	}
	if _, err := reader.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("end error = %v, want EOF", err)
	}
}

func TestRealCompressedPCAPNGFixture(t *testing.T) {
	input, err := os.Open("../../testdata/wep.pcapng.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	reader, err := NewReader(input, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if reader.Format() != FormatPCAPNG {
		t.Fatalf("format = %v, want pcapng", reader.Format())
	}
	count := 0
	for {
		packet, err := reader.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if uint32(len(packet.Data)) > DefaultLimits().MaxPacketBytes || packet.Original < uint32(len(packet.Data)) {
			t.Fatalf("invalid packet lengths: captured=%d original=%d", len(packet.Data), packet.Original)
		}
		count++
	}
	if count == 0 {
		t.Fatal("fixture contained no packets")
	}
}

func TestPCAPAllMagicVariants(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name  string
		magic [4]byte
		order binary.ByteOrder
		nano  bool
	}{
		{name: "little-micro", magic: [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, order: binary.LittleEndian},
		{name: "big-micro", magic: [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, order: binary.BigEndian},
		{name: "little-nano", magic: [4]byte{0x4d, 0x3c, 0xb2, 0xa1}, order: binary.LittleEndian, nano: true},
		{name: "big-nano", magic: [4]byte{0xa1, 0xb2, 0x3c, 0x4d}, order: binary.BigEndian, nano: true},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			data := convertPCAP(fixture, variant.magic, variant.order, variant.nano)
			reader, err := NewReader(bytes.NewReader(data), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			packet, err := reader.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			if len(packet.Data) != 30 {
				t.Fatalf("captured length = %d, want 30", len(packet.Data))
			}
		})
	}
}

func convertPCAP(source []byte, magic [4]byte, order binary.ByteOrder, nano bool) []byte {
	data := append([]byte(nil), source...)
	data[0], data[1], data[2], data[3] = magic[0], magic[1], magic[2], magic[3]
	for offset := 4; offset < 24; offset += 2 {
		value := binary.LittleEndian.Uint16(source[offset : offset+2])
		order.PutUint16(data[offset:offset+2], value)
	}
	for offset := 24; offset < 40; offset += 4 {
		value := binary.LittleEndian.Uint32(source[offset : offset+4])
		if nano && offset == 28 {
			value *= 1000
		}
		order.PutUint32(data[offset:offset+4], value)
	}
	return data
}

func TestRejectUnknownFormat(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte("not a capture file")), DefaultLimits())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("error = %v, want unknown-format error", err)
	}
}

func TestRejectOversizedPacketBeforeAllocation(t *testing.T) {
	data, err := os.ReadFile("../../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[32:36], DefaultLimits().MaxPacketBytes+1)
	reader, err := NewReader(bytes.NewReader(data), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadPacket(); err == nil {
		t.Fatal("expected packet size error")
	}
}

func TestDecompressedSizeLimit(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(fixture); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxDecompressedBytes = 16
	_, err = NewReader(bytes.NewReader(compressed.Bytes()), limits)
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("error = %v, want size limit error", err)
	}
}

func FuzzCaptureReader(f *testing.F) {
	pcap, err := os.ReadFile("../../testdata/arp.pcap")
	if err != nil {
		f.Fatal(err)
	}
	pcapng, err := os.ReadFile("../../testdata/wep.pcapng.gz")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pcap)
	f.Add(pcapng)
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a})
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := Limits{
			MaxFileBytes:         1 << 20,
			MaxDecompressedBytes: 1 << 20,
			MaxPacketBytes:       256 << 10,
			MaxBlockBytes:        512 << 10,
			MaxInterfaces:        32,
		}
		reader, err := NewReader(bytes.NewReader(data), limits)
		if err != nil {
			return
		}
		for index := 0; index < 128; index++ {
			_, err := reader.ReadPacket()
			if err != nil {
				return
			}
		}
	})
}
