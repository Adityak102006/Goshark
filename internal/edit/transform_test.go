package edit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"goshark/internal/capturefile"
)

func TestParseAndMergeRanges(t *testing.T) {
	ranges, err := ParseRanges("8,1-3,3-5,12-12")
	if err != nil {
		t.Fatal(err)
	}
	want := []Range{{First: 1, Last: 5}, {First: 8, Last: 8}, {First: 12, Last: 12}}
	if len(ranges) != len(want) {
		t.Fatalf("ranges = %#v", ranges)
	}
	for index := range want {
		if ranges[index] != want[index] {
			t.Fatalf("range[%d] = %#v, want %#v", index, ranges[index], want[index])
		}
	}
}

func TestParseInvalidRanges(t *testing.T) {
	for _, value := range []string{"0", "3-2", "1,,4", "1-", "-3", "1-2-3"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseRanges(value); err == nil {
				t.Fatalf("ParseRanges(%q) succeeded", value)
			}
		})
	}
}

func TestEditRealCaptureWithRangeSnaplenAndTimeShift(t *testing.T) {
	reader, err := capturefile.OpenFile("../../testdata/http.pcap", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	outputPath := filepath.Join(t.TempDir(), "edited.pcap")
	shift := 3 * time.Second
	stats, err := Run(reader, outputPath, Options{
		KeepRanges: []Range{{First: 1, Last: 1}},
		Snaplen:    64,
		TimeShift:  shift,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 1 || stats.Written != 1 || stats.Parts != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	output, err := capturefile.OpenFile(outputPath, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	packet, err := output.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Data) != 64 || packet.Original != 207 {
		t.Fatalf("packet lengths = captured %d original %d", len(packet.Data), packet.Original)
	}
	if packet.Timestamp.Sub(time.Date(2002, 12, 31, 13, 55, 31, 300_000_000, time.UTC)) != shift {
		t.Fatalf("timestamp = %s", packet.Timestamp)
	}
	if _, err := output.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("end error = %v, want EOF", err)
	}
}

func TestSplitRealCaptureByPacketCount(t *testing.T) {
	countReader, err := capturefile.OpenFile("../../testdata/wep.pcapng.gz", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for {
		_, err := countReader.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			countReader.Close()
			t.Fatal(err)
		}
		count++
	}
	if err := countReader.Close(); err != nil {
		t.Fatal(err)
	}
	if count < 2 {
		t.Fatalf("fixture packet count = %d", count)
	}
	reader, err := capturefile.OpenFile("../../testdata/wep.pcapng.gz", capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	outputPath := filepath.Join(t.TempDir(), "split.pcap")
	stats, err := Run(reader, outputPath, Options{SplitCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Written != count || stats.Parts != count {
		t.Fatalf("stats = %+v, expected %d one-packet parts", stats, count)
	}
	for part := uint64(1); part <= count; part++ {
		path := splitName(outputPath, part)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing split %s: %v", path, err)
		}
	}
}

func TestTimeWindowBoundaries(t *testing.T) {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Second)
	for _, test := range []struct {
		timestamp time.Time
		want      bool
	}{
		{timestamp: start.Add(-time.Nanosecond), want: false},
		{timestamp: start, want: true},
		{timestamp: end, want: true},
		{timestamp: end.Add(time.Nanosecond), want: false},
	} {
		if got := inTimeWindow(test.timestamp, &start, &end); got != test.want {
			t.Fatalf("inTimeWindow(%s) = %v, want %v", test.timestamp, got, test.want)
		}
	}
}
