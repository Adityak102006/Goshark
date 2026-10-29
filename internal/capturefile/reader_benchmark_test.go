package capturefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func BenchmarkReadMillionPacketsFromRealFrame(b *testing.B) {
	input, err := OpenFile("../../testdata/arp.pcap", DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}
	packet, err := input.ReadPacket()
	if err != nil {
		input.Close()
		b.Fatal(err)
	}
	if err := input.Close(); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "million.pcap")
	file, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(16<<20, packet.LinkType); err != nil {
		file.Close()
		b.Fatal(err)
	}
	const packetCount = uint64(1_000_000)
	captureInfo := gopacket.CaptureInfo{
		Timestamp:     packet.Timestamp,
		CaptureLength: len(packet.Data),
		Length:        int(packet.Original),
	}
	for index := uint64(0); index < packetCount; index++ {
		if err := writer.WritePacket(captureInfo, packet.Data); err != nil {
			file.Close()
			b.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		b.Fatal(err)
	}
	if err := file.Close(); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		reader, err := OpenFile(path, DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		var readCount uint64
		var packetBuffer []byte
		for {
			packet, err := reader.ReadPacketInto(packetBuffer)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				reader.Close()
				b.Fatal(err)
			}
			packetBuffer = packet.Data
			readCount++
		}
		if err := reader.Close(); err != nil {
			b.Fatal(err)
		}
		if readCount != packetCount {
			b.Fatalf("read %d packets, want %d", readCount, packetCount)
		}
	}
	b.ReportMetric(float64(packetCount*uint64(b.N))/b.Elapsed().Seconds(), "packets/s")
}
