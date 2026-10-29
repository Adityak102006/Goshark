package capturefile

import (
	"errors"
	"io"
	"os"
	"testing"
)

func TestReadPacketIntoReusesCallerBuffer(t *testing.T) {
	for _, path := range []string{"../../testdata/http.pcap", "../../testdata/wep.pcapng.gz"} {
		t.Run(path, func(t *testing.T) {
			reader, err := OpenFile(path, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			buffer := make([]byte, 0, 1<<20)
			storage := buffer[:cap(buffer)]
			address := &storage[0]
			seen := 0
			for {
				packet, err := reader.ReadPacketInto(buffer)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(packet.Data) > 0 && &packet.Data[0] != address {
					t.Fatal("packet data did not use caller-owned buffer")
				}
				buffer = packet.Data
				seen++
			}
			if seen == 0 {
				t.Fatal("fixture contained no packets")
			}
		})
	}
}

func TestOpenFileRejectsNonRegularFiles(t *testing.T) {
	_, err := OpenFile(os.TempDir(), DefaultLimits())
	if err == nil {
		t.Fatal("directory was accepted as a capture file")
	}
}
