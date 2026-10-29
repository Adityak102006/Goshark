package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"goshark/internal/capturefile"
	"goshark/internal/displayfilter"
	"goshark/internal/ipc"
)

func (s *Server) saveCapture(ctx context.Context, request ipc.Message, connection net.Conn) (runErr error) {
	streamContext, _, stopWatching := watchClient(ctx, connection)
	defer func() {
		runErr = errors.Join(runErr, stopWatching())
	}()
	filter, err := displayfilter.Compile(request.DisplayFilter)
	if err != nil {
		return err
	}
	if request.CaptureID == "" {
		source, err := filepath.Abs(request.Path)
		if err != nil {
			return err
		}
		destination, err := filepath.Abs(request.OutputPath)
		if err != nil {
			return err
		}
		if filepath.Clean(source) == filepath.Clean(destination) {
			return errors.New("export destination must differ from the source capture")
		}
		if sourceInfo, sourceErr := os.Stat(source); sourceErr == nil {
			if destinationInfo, destinationErr := os.Stat(destination); destinationErr == nil && os.SameFile(sourceInfo, destinationInfo) {
				return errors.New("export destination must not be the source capture file")
			}
		}
	}
	sourcePath := request.Path
	var captureTruncated bool
	if request.CaptureID != "" {
		snapshotPath, cleanup, truncated, err := s.snapshotLiveCapture(streamContext, request.CaptureID)
		if err != nil {
			return err
		}
		sourcePath = snapshotPath
		captureTruncated = truncated
		defer cleanup()
	}
	output, err := capturefile.NewAtomicFile(request.OutputPath)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, output.Close())
	}()
	var captured uint64
	var exported uint64
	var linkType uint32
	var headerWritten bool
	writePacket := func(packet capturefile.Packet) error {
		if err := streamContext.Err(); err != nil {
			return err
		}
		captured++
		if !filter.Match(packet.Data, packet.LinkType, packet.Original) {
			return nil
		}
		if !headerWritten {
			if err := capturefile.WritePCAPHeader(output.File(), capturefile.DefaultLimits().MaxPacketBytes, packet.LinkType); err != nil {
				return err
			}
			linkType = uint32(packet.LinkType)
			headerWritten = true
		} else if linkType != uint32(packet.LinkType) {
			return errors.New("classic pcap export cannot represent mixed link types")
		}
		if err := capturefile.WritePCAPPacket(output.File(), packet, capturefile.DefaultLimits().MaxPacketBytes); err != nil {
			return err
		}
		exported++
		return nil
	}
	reader, err := capturefile.OpenFile(sourcePath, capturefile.DefaultLimits())
	if err != nil {
		return err
	}
	var packetData []byte
	for {
		packet, err := reader.ReadPacketInto(packetData)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Join(fmt.Errorf("read packet %d for export: %w", captured+1, err), reader.Close())
		}
		packetData = packet.Data
		if err := writePacket(packet); err != nil {
			return errors.Join(fmt.Errorf("export packet %d: %w", captured+1, err), reader.Close())
		}
	}
	if err := reader.Close(); err != nil {
		return err
	}
	if exported == 0 {
		return errors.New("no packets matched the export filter")
	}
	if err := output.Commit(); err != nil {
		return err
	}
	return writeMessage(connection, ipc.Message{
		ID: request.ID, Type: "response", Format: "pcap", Captured: captured, Displayed: exported, Truncated: captureTruncated,
	})
}
