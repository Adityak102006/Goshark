package capturefile

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Format uint8

const (
	FormatPCAP Format = iota + 1
	FormatPCAPNG
)

type Limits struct {
	MaxFileBytes         int64
	MaxDecompressedBytes int64
	MaxPacketBytes       uint32
	MaxBlockBytes        uint32
	MaxInterfaces        uint32
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:         1 << 30,
		MaxDecompressedBytes: 1 << 30,
		MaxPacketBytes:       16 << 20,
		MaxBlockBytes:        (16 << 20) + (64 << 10),
		MaxInterfaces:        1024,
	}
}

func OpenFile(path string, limits Limits) (*Reader, error) {
	if path == "" {
		return nil, errors.New("capture path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve capture path: %w", err)
	}
	provided, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect capture path: %w", err)
	}
	if provided.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("capture path must not be a symbolic link")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("canonicalize capture path: %w", err)
	}
	root, err := os.OpenRoot(filepath.Dir(canonical))
	if err != nil {
		return nil, fmt.Errorf("open capture directory: %w", err)
	}
	defer root.Close()
	name := filepath.Base(canonical)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect canonical capture: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("capture path is not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open capture: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("inspect opened capture: %w", err), closeErr)
	}
	if !os.SameFile(before, after) {
		closeErr := file.Close()
		return nil, errors.Join(errors.New("capture path changed while it was being opened"), closeErr)
	}
	if after.Size() > limits.MaxFileBytes {
		closeErr := file.Close()
		return nil, errors.Join(ErrSizeLimit, closeErr)
	}
	reader, err := NewReader(file, limits)
	if err != nil {
		closeErr := file.Close()
		return nil, errors.Join(err, closeErr)
	}
	reader.closer = file
	return reader, nil
}

func (r *Reader) Close() error {
	if r.closer == nil {
		return nil
	}
	err := r.closer.Close()
	r.closer = nil
	return err
}

type Packet struct {
	Data      []byte
	Timestamp time.Time
	Original  uint32
	Interface uint32
	LinkType  layers.LinkType
}

type Reader struct {
	input            *bufio.Reader
	format           Format
	limits           Limits
	pcap             pcapState
	interfaces       []interfaceState
	blockBuffer      []byte
	pcapPacketHeader [16]byte
	blockHeader      [8]byte
	closer           io.Closer
}

type pcapState struct {
	order    binary.ByteOrder
	nano     bool
	snaplen  uint32
	linkType layers.LinkType
}

type interfaceState struct {
	linkType layers.LinkType
	snaplen  uint32
	base     uint64
	offset   int64
}

type cappedReader struct {
	input     io.Reader
	remaining int64
}

var (
	ErrUnknownFormat = errors.New("unknown capture format")
	ErrSizeLimit     = errors.New("capture size limit exceeded")
)

func (r *cappedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.input.Read(probe[:])
		if n > 0 {
			return 0, ErrSizeLimit
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.input.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func NewReader(input io.Reader, limits Limits) (*Reader, error) {
	if input == nil || limits.MaxFileBytes < 1 || limits.MaxFileBytes > 1<<40 || limits.MaxDecompressedBytes < 1 || limits.MaxDecompressedBytes > 1<<40 || limits.MaxPacketBytes < 1 || limits.MaxPacketBytes > 64<<20 || limits.MaxBlockBytes < limits.MaxPacketBytes+32 || limits.MaxBlockBytes > 65<<20 || limits.MaxInterfaces < 1 || limits.MaxInterfaces > 4096 {
		return nil, errors.New("invalid capture reader limits or input")
	}
	raw := bufio.NewReader(&cappedReader{input: input, remaining: limits.MaxFileBytes})
	magic, err := raw.Peek(2)
	if err != nil {
		return nil, fmt.Errorf("read capture signature: %w", err)
	}
	payload := io.Reader(raw)
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("open gzip capture: %w", err)
		}
		payload = &cappedReader{input: gz, remaining: limits.MaxDecompressedBytes}
	}
	stream := bufio.NewReader(payload)
	innerMagic, err := stream.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("read capture signature: %w", err)
	}
	reader := &Reader{input: stream, limits: limits}
	switch {
	case innerMagic[0] == 0x0a && innerMagic[1] == 0x0d && innerMagic[2] == 0x0d && innerMagic[3] == 0x0a:
		reader.format = FormatPCAPNG
		if err := reader.readSectionHeader(); err != nil {
			return nil, fmt.Errorf("read pcapng section header: %w", err)
		}
	case isPCAPMagic(innerMagic):
		reader.format = FormatPCAP
		if err := reader.readPCAPHeader(); err != nil {
			return nil, fmt.Errorf("read pcap header: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: %02x%02x%02x%02x", ErrUnknownFormat, innerMagic[0], innerMagic[1], innerMagic[2], innerMagic[3])
	}
	return reader, nil
}

func (r *Reader) Format() Format {
	return r.format
}

// ReadPacket reads the next packet into an independently allocated byte slice.
func (r *Reader) ReadPacket() (Packet, error) {
	return r.readPacket(nil)
}

// ReadPacketInto reuses buffer capacity; returned packet data is valid only until the caller reuses that buffer.
func (r *Reader) ReadPacketInto(buffer []byte) (Packet, error) {
	return r.readPacket(buffer)
}

func (r *Reader) readPacket(buffer []byte) (Packet, error) {
	if r.format == FormatPCAP {
		return r.readPCAPPacket(buffer)
	}
	return r.readPCAPNGPacket(buffer)
}

func isPCAPMagic(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	return magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1 ||
		magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4 ||
		magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1 ||
		magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d
}

func (r *Reader) readPCAPHeader() error {
	var header [24]byte
	if _, err := io.ReadFull(r.input, header[:]); err != nil {
		return err
	}
	switch {
	case header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1:
		r.pcap.order = binary.LittleEndian
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4:
		r.pcap.order = binary.BigEndian
	case header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1:
		r.pcap.order = binary.LittleEndian
		r.pcap.nano = true
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d:
		r.pcap.order = binary.BigEndian
		r.pcap.nano = true
	default:
		return fmt.Errorf("%w: invalid pcap magic", ErrUnknownFormat)
	}
	if major, minor := r.pcap.order.Uint16(header[4:6]), r.pcap.order.Uint16(header[6:8]); major != 2 || minor != 4 {
		return fmt.Errorf("unsupported pcap version %d.%d", major, minor)
	}
	r.pcap.snaplen = r.pcap.order.Uint32(header[16:20])
	if r.pcap.snaplen == 0 {
		return errors.New("pcap snaplen is zero")
	}
	link := r.pcap.order.Uint32(header[20:24]) & 0xffff
	r.pcap.linkType = layers.LinkType(link)
	return nil
}

func (r *Reader) readPCAPPacket(buffer []byte) (Packet, error) {
	header := r.pcapPacketHeader[:]
	if _, err := io.ReadFull(r.input, header); err != nil {
		return Packet{}, err
	}
	seconds := r.pcap.order.Uint32(header[0:4])
	fraction := r.pcap.order.Uint32(header[4:8])
	captured := r.pcap.order.Uint32(header[8:12])
	original := r.pcap.order.Uint32(header[12:16])
	if captured > r.limits.MaxPacketBytes {
		return Packet{}, fmt.Errorf("pcap packet capture length %d exceeds limit %d", captured, r.limits.MaxPacketBytes)
	}
	if captured > r.pcap.snaplen || captured > original {
		return Packet{}, fmt.Errorf("invalid pcap packet lengths: captured=%d snaplen=%d original=%d", captured, r.pcap.snaplen, original)
	}
	if r.pcap.nano && fraction >= 1_000_000_000 || !r.pcap.nano && fraction >= 1_000_000 {
		return Packet{}, errors.New("invalid pcap timestamp fraction")
	}
	data := packetBuffer(buffer, int(captured))
	if _, err := io.ReadFull(r.input, data); err != nil {
		return Packet{}, err
	}
	nanoseconds := int64(fraction)
	if !r.pcap.nano {
		nanoseconds *= 1000
	}
	return Packet{
		Data:      data,
		Timestamp: time.Unix(int64(seconds), nanoseconds).UTC(),
		Original:  original,
		LinkType:  r.pcap.linkType,
	}, nil
}

func packetBuffer(buffer []byte, length int) []byte {
	if cap(buffer) < length {
		return make([]byte, length)
	}
	return buffer[:length]
}

func (r *Reader) readSectionHeader() error {
	var header [12]byte
	if _, err := io.ReadFull(r.input, header[:]); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch {
	case header[8] == 0x4d && header[9] == 0x3c && header[10] == 0x2b && header[11] == 0x1a:
		order = binary.LittleEndian
	case header[8] == 0x1a && header[9] == 0x2b && header[10] == 0x3c && header[11] == 0x4d:
		order = binary.BigEndian
	default:
		return errors.New("invalid pcapng byte-order magic")
	}
	blockLength := order.Uint32(header[4:8])
	if err := validateBlockLength(blockLength, 28, r.limits.MaxBlockBytes); err != nil {
		return err
	}
	remaining := make([]byte, int(blockLength)-12)
	if _, err := io.ReadFull(r.input, remaining); err != nil {
		return err
	}
	if order.Uint32(remaining[len(remaining)-4:]) != blockLength {
		return errors.New("pcapng section block length trailer mismatch")
	}
	if order.Uint16(remaining[0:2]) != 1 {
		return fmt.Errorf("unsupported pcapng major version %d", order.Uint16(remaining[0:2]))
	}
	r.interfaces = r.interfaces[:0]
	r.pcap.order = order
	return nil
}

func validateBlockLength(length, minimum, maximum uint32) error {
	if length < minimum || length&3 != 0 || length > maximum {
		return fmt.Errorf("invalid pcapng block length %d", length)
	}
	return nil
}

func (r *Reader) readPCAPNGPacket(packetData []byte) (Packet, error) {
	for {
		header := r.blockHeader[:]
		if _, err := io.ReadFull(r.input, header); err != nil {
			return Packet{}, err
		}
		blockType := r.pcap.order.Uint32(header[0:4])
		if blockType == 0x0a0d0d0a {
			if err := r.readSectionHeaderAfterType(header); err != nil {
				return Packet{}, err
			}
			continue
		}
		blockLength := r.pcap.order.Uint32(header[4:8])
		if err := validateBlockLength(blockLength, 12, r.limits.MaxBlockBytes); err != nil {
			return Packet{}, err
		}
		blockSize := int(blockLength) - 8
		r.blockBuffer = packetBuffer(r.blockBuffer, blockSize)
		bodyAndTrailer := r.blockBuffer
		if _, err := io.ReadFull(r.input, bodyAndTrailer); err != nil {
			return Packet{}, err
		}
		body := bodyAndTrailer[:len(bodyAndTrailer)-4]
		if r.pcap.order.Uint32(bodyAndTrailer[len(bodyAndTrailer)-4:]) != blockLength {
			return Packet{}, errors.New("pcapng block length trailer mismatch")
		}
		switch blockType {
		case 1:
			if err := r.readInterface(body); err != nil {
				return Packet{}, err
			}
		case 2:
			packet, ok, err := r.packetBlock(body, packetData)
			if err != nil || ok {
				return packet, err
			}
		case 3:
			packet, ok, err := r.simplePacketBlock(body, packetData)
			if err != nil || ok {
				return packet, err
			}
		case 6:
			packet, err := r.enhancedPacketBlock(body, packetData)
			return packet, err
		}
	}
}

func (r *Reader) readSectionHeaderAfterType(header []byte) error {
	var bom [4]byte
	if _, err := io.ReadFull(r.input, bom[:]); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch {
	case bom == [4]byte{0x4d, 0x3c, 0x2b, 0x1a}:
		order = binary.LittleEndian
	case bom == [4]byte{0x1a, 0x2b, 0x3c, 0x4d}:
		order = binary.BigEndian
	default:
		return errors.New("invalid pcapng byte-order magic")
	}
	blockLength := order.Uint32(header[4:8])
	if err := validateBlockLength(blockLength, 28, r.limits.MaxBlockBytes); err != nil {
		return err
	}
	remaining := make([]byte, int(blockLength)-12)
	if _, err := io.ReadFull(r.input, remaining); err != nil {
		return err
	}
	if order.Uint32(remaining[len(remaining)-4:]) != blockLength {
		return errors.New("pcapng section block length trailer mismatch")
	}
	if order.Uint16(remaining[0:2]) != 1 {
		return fmt.Errorf("unsupported pcapng major version %d", order.Uint16(remaining[0:2]))
	}
	r.interfaces = r.interfaces[:0]
	r.pcap.order = order
	return nil
}

func (r *Reader) readInterface(body []byte) error {
	if len(body) < 8 || uint64(len(r.interfaces)) >= uint64(r.limits.MaxInterfaces) {
		return errors.New("invalid or excessive pcapng interface count")
	}
	iface := interfaceState{
		linkType: layers.LinkType(r.pcap.order.Uint16(body[0:2])),
		snaplen:  r.pcap.order.Uint32(body[4:8]),
		base:     1_000_000,
	}
	if err := r.readInterfaceOptions(body[8:], &iface); err != nil {
		return err
	}
	r.interfaces = append(r.interfaces, iface)
	return nil
}

func (r *Reader) readInterfaceOptions(options []byte, iface *interfaceState) error {
	for len(options) > 0 {
		if len(options) < 4 {
			return errors.New("truncated pcapng interface option")
		}
		code := r.pcap.order.Uint16(options[0:2])
		length := uint32(r.pcap.order.Uint16(options[2:4]))
		options = options[4:]
		if code == 0 {
			if length != 0 {
				return errors.New("invalid pcapng end-of-options marker")
			}
			return nil
		}
		padded := (length + 3) &^ 3
		if uint64(padded) > uint64(len(options)) {
			return errors.New("pcapng option exceeds interface block")
		}
		value := options[:length]
		switch code {
		case 9:
			if len(value) != 1 {
				return errors.New("invalid pcapng timestamp resolution")
			}
			resolution := value[0]
			power := uint32(resolution & 0x7f)
			if resolution&0x80 != 0 {
				if power > 63 {
					return errors.New("unsupported binary timestamp resolution")
				}
				iface.base = uint64(1) << power
			} else {
				if power > 19 {
					return errors.New("unsupported decimal timestamp resolution")
				}
				iface.base = 1
				for index := uint32(0); index < power; index++ {
					iface.base *= 10
				}
			}
		case 14:
			if len(value) != 8 {
				return errors.New("invalid pcapng timestamp offset")
			}
			offset := r.pcap.order.Uint64(value)
			if offset <= math.MaxInt64 {
				iface.offset = int64(offset)
			} else {
				magnitude := ^offset + 1
				if magnitude > uint64(math.MaxInt64) {
					iface.offset = math.MinInt64
				} else {
					iface.offset = -int64(magnitude)
				}
			}
		}
		options = options[padded:]
	}
	return nil
}

func (r *Reader) packetBlock(body, packetData []byte) (Packet, bool, error) {
	if len(body) < 20 {
		return Packet{}, false, errors.New("truncated pcapng packet block")
	}
	ifaceID := uint32(r.pcap.order.Uint16(body[0:2]))
	if uint64(ifaceID) >= uint64(len(r.interfaces)) {
		return Packet{}, false, errors.New("pcapng packet references missing interface")
	}
	hi := r.pcap.order.Uint32(body[4:8])
	lo := r.pcap.order.Uint32(body[8:12])
	captured := r.pcap.order.Uint32(body[12:16])
	original := r.pcap.order.Uint32(body[16:20])
	return r.makeNGPacket(ifaceID, uint64(hi)<<32|uint64(lo), captured, original, body[20:], packetData)
}

func (r *Reader) simplePacketBlock(body, packetData []byte) (Packet, bool, error) {
	if len(body) < 4 || len(r.interfaces) == 0 {
		return Packet{}, false, errors.New("truncated pcapng simple packet block or missing interface")
	}
	original := r.pcap.order.Uint32(body[0:4])
	captured := original
	iface := r.interfaces[0]
	if iface.snaplen != 0 && captured > iface.snaplen {
		captured = iface.snaplen
	}
	if captured > r.limits.MaxPacketBytes {
		return Packet{}, false, fmt.Errorf("pcapng packet capture length %d exceeds limit %d", captured, r.limits.MaxPacketBytes)
	}
	padded := (captured + 3) &^ 3
	available := len(body) - 4
	if available < 0 || int64(padded) > int64(available) {
		return Packet{}, false, errors.New("pcapng simple packet data exceeds block")
	}
	data := packetBuffer(packetData, int(captured))
	copy(data, body[4:4+captured])
	return Packet{Data: data, Original: original, LinkType: iface.linkType}, true, nil
}

func (r *Reader) enhancedPacketBlock(body, packetData []byte) (Packet, error) {
	if len(body) < 20 {
		return Packet{}, errors.New("truncated pcapng enhanced packet block")
	}
	ifaceID := r.pcap.order.Uint32(body[0:4])
	if uint64(ifaceID) >= uint64(len(r.interfaces)) {
		return Packet{}, errors.New("pcapng enhanced packet references missing interface")
	}
	hi := r.pcap.order.Uint32(body[4:8])
	lo := r.pcap.order.Uint32(body[8:12])
	captured := r.pcap.order.Uint32(body[12:16])
	original := r.pcap.order.Uint32(body[16:20])
	packet, _, err := r.makeNGPacket(ifaceID, uint64(hi)<<32|uint64(lo), captured, original, body[20:], packetData)
	return packet, err
}

func (r *Reader) makeNGPacket(ifaceID uint32, timestamp uint64, captured, original uint32, dataAndOptions, packetData []byte) (Packet, bool, error) {
	if captured > r.limits.MaxPacketBytes {
		return Packet{}, false, fmt.Errorf("pcapng packet capture length %d exceeds limit %d", captured, r.limits.MaxPacketBytes)
	}
	if captured > original {
		return Packet{}, false, errors.New("pcapng capture length exceeds original packet length")
	}
	padded := (captured + 3) &^ 3
	if padded < captured || uint64(padded) > uint64(len(dataAndOptions)) {
		return Packet{}, false, errors.New("pcapng packet data exceeds block")
	}
	iface := r.interfaces[ifaceID]
	nanos, err := timestampNanos(timestamp%iface.base, iface.base)
	if err != nil {
		return Packet{}, false, err
	}
	seconds := timestamp / iface.base
	if seconds > math.MaxInt64 || iface.offset > 0 && int64(seconds) > math.MaxInt64-iface.offset || iface.offset < 0 && int64(seconds) < math.MinInt64-iface.offset {
		return Packet{}, false, errors.New("pcapng timestamp out of range")
	}
	data := packetBuffer(packetData, int(captured))
	copy(data, dataAndOptions[:captured])
	return Packet{
		Data:      data,
		Timestamp: time.Unix(int64(seconds)+iface.offset, nanos).UTC(),
		Original:  original,
		Interface: ifaceID,
		LinkType:  iface.linkType,
	}, true, nil
}

func timestampNanos(remainder, base uint64) (int64, error) {
	if base == 0 {
		return 0, errors.New("pcapng timestamp resolution is zero")
	}
	hi, lo := bits.Mul64(remainder, 1_000_000_000)
	if hi >= base {
		return 0, errors.New("pcapng timestamp fraction out of range")
	}
	nanos, _ := bits.Div64(hi, lo, base)
	if nanos > 999_999_999 || nanos > uint64(math.MaxInt64) {
		return 0, errors.New("pcapng timestamp fraction out of range")
	}
	return int64(nanos), nil
}

func (r *Reader) String() string {
	return fmt.Sprintf("capture format %d", r.format)
}

var _ gopacket.PacketDataSource = (*Reader)(nil)

func (r *Reader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	packet, err := r.ReadPacket()
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return packet.Data, gopacket.CaptureInfo{
		Timestamp:      packet.Timestamp,
		CaptureLength:  len(packet.Data),
		Length:         int(packet.Original),
		InterfaceIndex: int(packet.Interface),
	}, nil
}
