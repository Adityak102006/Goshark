package capturefile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/gopacket/gopacket/layers"
)

const maxPCAPPacketBytes = 16 << 20

// WritePCAPHeader writes a little-endian microsecond-resolution PCAP global header.
func WritePCAPHeader(writer io.Writer, snapshotLength uint32, linkType layers.LinkType) error {
	if snapshotLength == 0 || snapshotLength > maxPCAPPacketBytes {
		return errors.New("pcap snapshot length is outside the supported range")
	}
	var header [24]byte
	copy(header[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], snapshotLength)
	binary.LittleEndian.PutUint32(header[20:24], uint32(linkType))
	return writeAll(writer, header[:])
}

// WritePCAPPacket writes one packet record to a PCAP stream.
func WritePCAPPacket(writer io.Writer, packet Packet, snapshotLength uint32) error {
	capturedLength := len(packet.Data)
	if capturedLength == 0 || capturedLength > int(snapshotLength) || capturedLength > maxPCAPPacketBytes {
		return errors.New("pcap packet length is outside the configured snapshot limit")
	}
	originalLength := packet.Original
	if originalLength == 0 {
		originalLength = uint32(capturedLength)
	}
	if originalLength < uint32(capturedLength) {
		return errors.New("pcap original packet length is smaller than captured data")
	}
	seconds := packet.Timestamp.Unix()
	if seconds < 0 || uint64(seconds) > uint64(^uint32(0)) {
		return errors.New("pcap timestamp is outside the supported epoch range")
	}
	microseconds := uint32(packet.Timestamp.Nanosecond() / 1000) // #nosec G115 -- Nanosecond is in [0, 999999999], so microseconds is in [0, 999999].
	var header [16]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(seconds))
	binary.LittleEndian.PutUint32(header[4:8], microseconds)
	binary.LittleEndian.PutUint32(header[8:12], uint32(capturedLength))
	binary.LittleEndian.PutUint32(header[12:16], originalLength)
	if err := writeAll(writer, header[:]); err != nil {
		return fmt.Errorf("write pcap packet header: %w", err)
	}
	if err := writeAll(writer, packet.Data); err != nil {
		return fmt.Errorf("write pcap packet data: %w", err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return errors.New("writer returned an invalid byte count")
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
