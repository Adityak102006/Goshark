package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"goshark/internal/capturefile"
)

type Interface struct {
	Name        string
	Description string
	Addresses   []string
}

type LiveOptions struct {
	Interface      string
	SnapshotLength int32
	Promiscuous    bool
	CaptureFilter  string
	ReadTimeout    time.Duration
}

type CaptureStats struct {
	Received       int
	Dropped        int
	InterfaceDrops int
}

func ListInterfaces() ([]Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("enumerate capture interfaces: %w", err)
	}
	interfaces := make([]Interface, 0, len(devices))
	for _, device := range devices {
		entry := Interface{Name: device.Name, Description: device.Description}
		for _, address := range device.Addresses {
			if address.IP != nil {
				entry.Addresses = append(entry.Addresses, address.IP.String())
			}
		}
		interfaces = append(interfaces, entry)
	}
	return interfaces, nil
}

func Capture(ctx context.Context, options LiveOptions, onPacket func(capturefile.Packet) error) (CaptureStats, error) {
	if ctx == nil || onPacket == nil {
		return CaptureStats{}, errors.New("capture requires a context and packet handler")
	}
	if options.Interface == "" || strings.IndexByte(options.Interface, 0) >= 0 {
		return CaptureStats{}, errors.New("capture interface is required")
	}
	if options.SnapshotLength < 64 || options.SnapshotLength > 16<<20 {
		return CaptureStats{}, errors.New("snapshot length must be between 64 bytes and 16 MiB")
	}
	if len(options.CaptureFilter) > 4096 || strings.IndexByte(options.CaptureFilter, 0) >= 0 {
		return CaptureStats{}, errors.New("capture filter is too long or contains a NUL byte")
	}
	if options.ReadTimeout <= 0 || options.ReadTimeout > time.Second {
		return CaptureStats{}, errors.New("capture read timeout must be between 1 ns and 1 s")
	}
	interfaces, err := ListInterfaces()
	if err != nil {
		return CaptureStats{}, err
	}
	found := false
	for _, item := range interfaces {
		if item.Name == options.Interface {
			found = true
			break
		}
	}
	if !found {
		return CaptureStats{}, errors.New("capture interface is not present on this machine")
	}
	handle, err := pcap.OpenLive(options.Interface, options.SnapshotLength, options.Promiscuous, options.ReadTimeout)
	if err != nil {
		return CaptureStats{}, fmt.Errorf("open capture interface: %w", err)
	}
	defer handle.Close()
	if options.CaptureFilter != "" {
		if err := handle.SetBPFFilter(options.CaptureFilter); err != nil {
			return CaptureStats{}, fmt.Errorf("invalid capture filter: %w", err)
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return readStats(handle), err
		}
		data, info, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if ctx.Err() != nil {
				return readStats(handle), ctx.Err()
			}
			return readStats(handle), fmt.Errorf("read captured packet: %w", err)
		}
		if len(data) > int(options.SnapshotLength) || info.Length < len(data) || info.Length < 0 || uint64(info.Length) > uint64(^uint32(0)) {
			return readStats(handle), errors.New("capture backend returned invalid packet lengths")
		}
		packet := capturefile.Packet{
			Data:      append([]byte(nil), data...),
			Timestamp: info.Timestamp.UTC(),
			Original:  uint32(info.Length),
			LinkType:  layers.LinkType(handle.LinkType()),
		}
		if err := onPacket(packet); err != nil {
			return readStats(handle), fmt.Errorf("deliver captured packet: %w", err)
		}
	}
}

func readStats(handle *pcap.Handle) CaptureStats {
	stats, err := handle.Stats()
	if err != nil {
		return CaptureStats{}
	}
	return CaptureStats{
		Received:       stats.PacketsReceived,
		Dropped:        stats.PacketsDropped,
		InterfaceDrops: stats.PacketsIfDropped,
	}
}
