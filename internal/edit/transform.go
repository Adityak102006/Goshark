package edit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"

	"goshark/internal/capturefile"
)

type Range struct {
	First uint64
	Last  uint64
}

type Options struct {
	KeepRanges []Range
	Dedupe     bool
	SplitCount uint64
	TimeShift  time.Duration
	Snaplen    uint32
	StartTime  *time.Time
	EndTime    *time.Time
}

type Stats struct {
	Read       uint64
	Written    uint64
	Duplicates uint64
	Outside    uint64
	Parts      uint64
}

type sink struct {
	file     *capturefile.AtomicFile
	writer   *pcapgo.Writer
	linkType uint16
	path     string
}

func ParseRanges(value string) ([]Range, error) {
	if len(value) > 4096 {
		return nil, errors.New("packet range expression exceeds 4096 bytes")
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 256 {
		return nil, errors.New("packet range expression contains too many ranges")
	}
	ranges := make([]Range, 0, len(parts))
	for _, part := range parts {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 || bounds[0] == "" {
			return nil, fmt.Errorf("invalid packet range %q", part)
		}
		first, err := strconv.ParseUint(bounds[0], 10, 64)
		if err != nil || first == 0 {
			return nil, fmt.Errorf("invalid packet number in range %q", part)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(bounds[1], 10, 64)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid packet interval %q", part)
			}
		}
		ranges = append(ranges, Range{First: first, Last: last})
	}
	sort.Slice(ranges, func(left, right int) bool {
		if ranges[left].First == ranges[right].First {
			return ranges[left].Last < ranges[right].Last
		}
		return ranges[left].First < ranges[right].First
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		previous := &merged[len(merged)-1]
		if current.First <= previous.Last || previous.Last != ^uint64(0) && current.First == previous.Last+1 {
			if current.Last > previous.Last {
				previous.Last = current.Last
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged, nil
}

func Run(reader *capturefile.Reader, outputPath string, options Options) (stats Stats, runErr error) {
	if reader == nil || outputPath == "" {
		return stats, errors.New("input capture and output path are required")
	}
	if options.Snaplen > 16<<20 {
		return stats, errors.New("snaplen exceeds 16 MiB")
	}
	if options.SplitCount > 0 && options.SplitCount > 1<<40 {
		return stats, errors.New("split count is outside the supported range")
	}
	if options.StartTime != nil && options.EndTime != nil && options.StartTime.After(*options.EndTime) {
		return stats, errors.New("start time is after end time")
	}
	seen := make(map[[32]byte]struct{})
	var current *sink
	var inPart uint64
	var packetData []byte
	defer func() {
		if current != nil {
			runErr = errors.Join(runErr, current.close(false))
		}
	}()
	for {
		packet, err := reader.ReadPacketInto(packetData)
		if errors.Is(err, io.EOF) {
			if current != nil {
				if err := current.close(true); err != nil {
					return stats, err
				}
				current = nil
			}
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("read packet for editing: %w", err)
		}
		packetData = packet.Data
		stats.Read++
		packetNumber := stats.Read
		if !inRanges(packetNumber, options.KeepRanges) || !inTimeWindow(packet.Timestamp, options.StartTime, options.EndTime) {
			stats.Outside++
			continue
		}
		if options.Dedupe {
			key, err := fingerprint(packet.Data, uint16(packet.LinkType), packet.Original)
			if err != nil {
				return stats, err
			}
			if _, exists := seen[key]; exists {
				stats.Duplicates++
				continue
			}
			if len(seen) >= 1<<20 {
				return stats, errors.New("deduplication memory limit reached")
			}
			seen[key] = struct{}{}
		}
		if options.Snaplen > 0 && int64(len(packet.Data)) > int64(options.Snaplen) {
			packet.Data = packet.Data[:options.Snaplen]
		}
		packet.Timestamp = packet.Timestamp.Add(options.TimeShift)
		if current == nil || options.SplitCount > 0 && inPart >= options.SplitCount {
			if current != nil {
				if err := current.close(true); err != nil {
					return stats, err
				}
				current = nil
			}
			stats.Parts++
			partPath := outputPath
			if options.SplitCount > 0 {
				partPath = splitName(outputPath, stats.Parts)
			}
			current, err = openSink(partPath, packet, options.Snaplen)
			if err != nil {
				return stats, err
			}
			inPart = 0
		}
		if current.linkType != uint16(packet.LinkType) {
			return stats, errors.New("pcap output cannot contain packets from different link types")
		}
		if err := current.write(packet); err != nil {
			return stats, err
		}
		stats.Written++
		inPart++
	}
}

func inRanges(packetNumber uint64, ranges []Range) bool {
	if len(ranges) == 0 {
		return true
	}
	index := sort.Search(len(ranges), func(index int) bool {
		return ranges[index].Last >= packetNumber
	})
	return index < len(ranges) && packetNumber >= ranges[index].First
}

func inTimeWindow(timestamp time.Time, start, end *time.Time) bool {
	if start != nil && timestamp.Before(*start) {
		return false
	}
	if end != nil && timestamp.After(*end) {
		return false
	}
	return true
}

func fingerprint(data []byte, linkType uint16, original uint32) ([32]byte, error) {
	var metadata [6]byte
	binary.LittleEndian.PutUint16(metadata[:2], linkType)
	binary.LittleEndian.PutUint32(metadata[2:], original)
	hashValue := sha256.New()
	if _, err := hashValue.Write(metadata[:]); err != nil {
		return [32]byte{}, err
	}
	if _, err := hashValue.Write(data); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], hashValue.Sum(nil))
	return result, nil
}

func splitName(outputPath string, part uint64) string {
	extension := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, extension)
	return fmt.Sprintf("%s-%04d%s", base, part, extension)
}

func openSink(path string, packet capturefile.Packet, snaplen uint32) (*sink, error) {
	file, err := capturefile.NewAtomicFile(path)
	if err != nil {
		return nil, err
	}
	writer := pcapgo.NewWriter(file.File())
	if snaplen == 0 {
		snaplen = 16 << 20
	}
	if err := writer.WriteFileHeader(snaplen, packet.LinkType); err != nil {
		return nil, errors.Join(fmt.Errorf("write output pcap header: %w", err), file.Close())
	}
	return &sink{file: file, writer: writer, linkType: uint16(packet.LinkType), path: path}, nil
}

func (s *sink) write(packet capturefile.Packet) error {
	if err := s.writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     packet.Timestamp,
		CaptureLength: len(packet.Data),
		Length:        int(packet.Original),
	}, packet.Data); err != nil {
		return fmt.Errorf("write output packet to %s: %w", s.path, err)
	}
	return nil
}

func (s *sink) close(commit bool) error {
	if s == nil || s.file == nil {
		return nil
	}
	var commitErr error
	if commit {
		commitErr = s.file.Commit()
	}
	closeErr := s.file.Close()
	s.file = nil
	return errors.Join(commitErr, closeErr)
}

func NewTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp: %w", err)
	}
	return parsed.UTC(), nil
}
