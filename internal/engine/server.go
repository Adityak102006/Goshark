package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"goshark/internal/capture"
	"goshark/internal/capturefile"
	"goshark/internal/displayfilter"
	"goshark/internal/dissection"
	"goshark/internal/ipc"
)

type Server struct {
	sessionMu    sync.RWMutex
	sessions     map[string]*liveSession
	sessionOrder []string
}

func (s *Server) Handle(ctx context.Context, request ipc.Message, connection net.Conn) error {
	switch request.Operation {
	case "list_interfaces":
		return s.listInterfaces(request, connection)
	case "open_capture":
		return s.openCapture(ctx, request, connection)
	case "save_capture":
		return s.saveCapture(ctx, request, connection)
	case "packet_detail":
		return s.packetDetail(request, connection)
	case "packet_bytes":
		return s.packetBytes(request, connection)
	case "follow_tcp_stream":
		return s.followTCPStream(ctx, request, connection)
	case "start_capture":
		return s.startCapture(ctx, request, connection)
	default:
		return errors.New("unsupported engine operation")
	}
}

func (s *Server) listInterfaces(request ipc.Message, connection net.Conn) error {
	interfaces, err := capture.ListInterfaces()
	if err != nil {
		return err
	}
	result := make([]ipc.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		result = append(result, ipc.Interface{
			Name:        safeText(iface.Name),
			Description: safeText(iface.Description),
			Addresses:   sanitizeList(iface.Addresses),
		})
	}
	return writeMessage(connection, ipc.Message{ID: request.ID, Type: "response", Interfaces: result})
}

func (s *Server) openCapture(ctx context.Context, request ipc.Message, connection net.Conn) (runErr error) {
	streamContext, _, stopWatching := watchClient(ctx, connection)
	defer func() {
		runErr = errors.Join(runErr, stopWatching())
	}()
	filter, err := displayfilter.Compile(request.DisplayFilter)
	if err != nil {
		return err
	}
	reader, err := capturefile.OpenFile(request.Path, capturefile.DefaultLimits())
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, reader.Close())
	}()
	if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "response", Format: formatName(reader.Format())}); err != nil {
		return err
	}
	var packetData []byte
	var batch []ipc.Frame
	var captured uint64
	var displayed uint64
	for {
		if streamContext.Err() != nil {
			return streamContext.Err()
		}
		if request.Limit > 0 && captured >= uint64(request.Limit) {
			break
		}
		packet, err := reader.ReadPacketInto(packetData)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read capture packet: %w", err)
		}
		packetData = packet.Data
		captured++
		if !filter.Match(packet.Data, packet.LinkType, packet.Original) {
			continue
		}
		result, err := dissection.Dissect(packet.Data, packet.LinkType)
		if err != nil {
			return err
		}
		frame, err := frameSummary(captured, packet, result)
		if err != nil {
			return err
		}
		batch = append(batch, frame)
		displayed++
		if len(batch) == ipc.MaxFramesPerBatch {
			if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "batch", Frames: batch, Captured: captured, Displayed: displayed}); err != nil {
				return err
			}
			batch = make([]ipc.Frame, 0, ipc.MaxFramesPerBatch)
		}
		if request.Limit > 0 && captured >= uint64(request.Limit) {
			break
		}
	}
	if len(batch) > 0 {
		if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "batch", Frames: batch, Captured: captured, Displayed: displayed}); err != nil {
			return err
		}
	}
	return writeMessage(connection, ipc.Message{ID: request.ID, Type: "end", Captured: captured, Displayed: displayed})
}

func (s *Server) packetDetail(request ipc.Message, connection net.Conn) error {
	packet, err := s.packetForRequest(request)
	if err != nil {
		return err
	}
	result, err := dissection.Dissect(packet.Data, packet.LinkType)
	if err != nil {
		return err
	}
	protocols := make([]ipc.Protocol, 0, len(result.Protocols))
	for _, protocol := range result.Protocols {
		protocolStart, err := intToUint32(protocol.Start)
		if err != nil {
			return err
		}
		protocolLength, err := intToUint32(protocol.Length)
		if err != nil {
			return err
		}
		fields := make([]ipc.Field, 0, len(protocol.Fields))
		for _, field := range protocol.Fields {
			fieldStart, err := intToUint32(field.Bytes.Start)
			if err != nil {
				return err
			}
			fieldLength, err := intToUint32(field.Bytes.Length)
			if err != nil {
				return err
			}
			fields = append(fields, ipc.Field{
				Name:       safeText(field.Name),
				Value:      safeText(field.Value),
				ByteStart:  fieldStart,
				ByteLength: fieldLength,
			})
		}
		protocols = append(protocols, ipc.Protocol{
			Name:       safeText(protocol.Name),
			ByteStart:  protocolStart,
			ByteLength: protocolLength,
			Fields:     fields,
		})
	}
	totalBytes, err := intToUint32(len(packet.Data))
	if err != nil {
		return err
	}
	return writeMessage(connection, ipc.Message{
		ID:           request.ID,
		Type:         "response",
		PacketNumber: request.PacketNumber,
		TotalBytes:   totalBytes,
		Protocols:    protocols,
	})
}

func (s *Server) packetBytes(request ipc.Message, connection net.Conn) error {
	packet, err := s.packetForRequest(request)
	if err != nil {
		return err
	}
	start := uint64(request.ByteOffset)
	end := start + uint64(request.ByteLength)
	if end > uint64(len(packet.Data)) {
		return errors.New("requested packet byte range exceeds packet length")
	}
	totalBytes, err := intToUint32(len(packet.Data))
	if err != nil {
		return err
	}
	return writeMessage(connection, ipc.Message{
		ID:           request.ID,
		Type:         "response",
		PacketNumber: request.PacketNumber,
		ByteOffset:   request.ByteOffset,
		ByteLength:   request.ByteLength,
		TotalBytes:   totalBytes,
		More:         end < uint64(len(packet.Data)),
		Data:         append([]byte(nil), packet.Data[start:end]...),
	})
}

func (s *Server) packetForRequest(request ipc.Message) (capturefile.Packet, error) {
	if request.CaptureID != "" {
		return s.livePacket(request.CaptureID, request.PacketNumber)
	}
	reader, err := capturefile.OpenFile(request.Path, capturefile.DefaultLimits())
	if err != nil {
		return capturefile.Packet{}, err
	}
	defer reader.Close()
	var packetData []byte
	for number := uint64(1); number <= request.PacketNumber; number++ {
		packet, err := reader.ReadPacketInto(packetData)
		if errors.Is(err, io.EOF) {
			return capturefile.Packet{}, errors.New("packet number is outside the capture")
		}
		if err != nil {
			return capturefile.Packet{}, fmt.Errorf("read packet %d: %w", number, err)
		}
		packetData = packet.Data
		if number == request.PacketNumber {
			return packet, nil
		}
	}
	return capturefile.Packet{}, errors.New("packet number is outside the capture")
}

func (s *Server) startCapture(ctx context.Context, request ipc.Message, connection net.Conn) (runErr error) {
	filter, err := displayfilter.Compile(request.DisplayFilter)
	if err != nil {
		return err
	}
	captureID, err := s.createLiveSession()
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, s.finishLiveSession(captureID))
	}()
	if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "response", CaptureInterface: safeText(request.InterfaceName), CaptureID: captureID}); err != nil {
		return err
	}
	captureContext, cancel, stopWatching := watchClient(ctx, connection)
	defer func() {
		runErr = errors.Join(runErr, stopWatching())
	}()
	batch := make([]ipc.Frame, 0, ipc.MaxFramesPerBatch)
	var captured uint64
	var displayed uint64
	stats, captureErr := capture.Capture(captureContext, capture.LiveOptions{
		Interface:      request.InterfaceName,
		SnapshotLength: 262144,
		Promiscuous:    request.Promiscuous,
		CaptureFilter:  request.CaptureFilter,
		ReadTimeout:    200 * time.Millisecond,
	}, func(packet capturefile.Packet) error {
		captured++
		if err := s.storeLivePacket(captureID, captured, packet); err != nil {
			return err
		}
		if filter.Match(packet.Data, packet.LinkType, packet.Original) {
			result, err := dissection.Dissect(packet.Data, packet.LinkType)
			if err != nil {
				return err
			}
			frame, err := frameSummary(captured, packet, result)
			if err != nil {
				return err
			}
			batch = append(batch, frame)
			displayed++
		}
		if len(batch) == ipc.MaxFramesPerBatch {
			if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "batch", Frames: batch, Captured: captured, Displayed: displayed}); err != nil {
				return err
			}
			batch = make([]ipc.Frame, 0, ipc.MaxFramesPerBatch)
		}
		if request.Limit > 0 && captured >= uint64(request.Limit) {
			cancel()
		}
		return nil
	})
	cancel()
	finishErr := s.finishLiveSession(captureID)
	if captureErr != nil && !errors.Is(captureErr, context.Canceled) {
		return errors.Join(captureErr, finishErr)
	}
	if finishErr != nil {
		return finishErr
	}
	if len(batch) > 0 {
		if err := writeMessage(connection, ipc.Message{ID: request.ID, Type: "batch", Frames: batch, Captured: captured, Displayed: displayed}); err != nil {
			return err
		}
	}
	return writeMessage(connection, ipc.Message{
		ID:        request.ID,
		Type:      "end",
		Captured:  captured,
		Displayed: displayed,
		Dropped:   uint64(max(0, stats.Dropped)),
	})
}

func frameSummary(number uint64, packet capturefile.Packet, result dissection.Result) (ipc.Frame, error) {
	length, err := intToUint32(len(packet.Data))
	if err != nil {
		return ipc.Frame{}, err
	}
	linkType, err := intToUint16(int(packet.LinkType))
	if err != nil {
		return ipc.Frame{}, err
	}
	frame := ipc.Frame{
		Number:    number,
		Timestamp: packet.Timestamp.UTC().Format(time.RFC3339Nano),
		Length:    length,
		LinkType:  linkType,
	}
	for index := len(result.Protocols) - 1; index >= 0; index-- {
		name := result.Protocols[index].Name
		if name != "Payload" && name != "Padding" && name != "Dot11InformationElement" {
			frame.Protocol = safeText(name)
			break
		}
	}
	var transport string
	var flags string
	var httpMethod string
	var httpURI string
	var httpStatus string
	var dnsMessageType string
	var wifiFrameType string
	for _, protocol := range result.Protocols {
		for _, field := range protocol.Fields {
			switch {
			case field.Name == "Source" && (frame.Source == "" || protocol.Name == "IPv4" || protocol.Name == "IPv6"):
				frame.Source = safeText(field.Value)
			case field.Name == "Destination" && (frame.Destination == "" || protocol.Name == "IPv4" || protocol.Name == "IPv6"):
				frame.Destination = safeText(field.Value)
			case protocol.Name == "ARP" && field.Name == "Sender protocol address":
				frame.Source = safeText(field.Value)
			case protocol.Name == "ARP" && field.Name == "Target protocol address":
				frame.Destination = safeText(field.Value)
			case field.Name == "Source port":
				frame.SourcePort = safeText(field.Value)
			case field.Name == "Destination port":
				frame.DestinationPort = safeText(field.Value)
			case protocol.Name == "HTTP" && field.Name == "Method":
				httpMethod = safeText(field.Value)
			case protocol.Name == "HTTP" && field.Name == "Request URI":
				httpURI = safeText(field.Value)
			case protocol.Name == "HTTP" && field.Name == "Status":
				httpStatus = safeText(field.Value)
			case protocol.Name == "DNS" && field.Name == "Message type":
				dnsMessageType = safeText(field.Value)
			case protocol.Name == "Dot11" && field.Name == "Frame type":
				wifiFrameType = safeText(field.Value)
			case field.Name == "Flags":
				flags = safeText(field.Value)
			}
		}
		if protocol.Name == "TCP" || protocol.Name == "UDP" {
			transport = protocol.Name
		}
	}
	frame.Info = frame.Protocol
	if transport != "" && frame.SourcePort != "" && frame.DestinationPort != "" {
		frame.Info = fmt.Sprintf("%s %s → %s", transport, frame.SourcePort, frame.DestinationPort)
	}
	if frame.Protocol == "TLS" && frame.SourcePort != "" && frame.DestinationPort != "" {
		frame.Info = fmt.Sprintf("TLS %s → %s", frame.SourcePort, frame.DestinationPort)
	}
	if wifiFrameType != "" {
		frame.Info = "802.11 " + wifiFrameType
	}
	if dnsMessageType != "" {
		frame.Info = "DNS " + dnsMessageType
	}
	if httpMethod != "" {
		frame.Info = "HTTP " + httpMethod + " " + httpURI
	}
	if httpStatus != "" {
		frame.Info = "HTTP " + httpStatus
	}
	if flags != "" && httpMethod == "" && httpStatus == "" && dnsMessageType == "" {
		frame.Info += " [" + flags + "]"
	}
	frame.Info = safeText(frame.Info)
	if len(frame.Info) > 512 {
		frame.Info = frame.Info[:512]
	}
	return frame, nil
}

func intToUint32(value int) (uint32, error) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return 0, errors.New("packet metadata exceeds the IPC numeric range")
	}
	return uint32(value), nil
}

func intToUint16(value int) (uint16, error) {
	if value < 0 || value > int(^uint16(0)) {
		return 0, errors.New("packet link type exceeds the IPC numeric range")
	}
	return uint16(value), nil
}

func formatName(format capturefile.Format) string {
	if format == capturefile.FormatPCAPNG {
		return "pcapng"
	}
	return "pcap"
}

func sanitizeList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, safeText(value))
	}
	return result
}

func safeText(value string) string {
	var safe strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == 0x1b {
			safe.WriteByte('?')
		} else {
			safe.WriteRune(character)
		}
	}
	return safe.String()
}

func watchClient(parent context.Context, connection net.Conn) (context.Context, context.CancelFunc, func() error) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ipc.ReadMessage(connection)
		if err != nil {
			cancel()
			return
		}
		cancel()
	}()
	stop := func() error {
		cancel()
		if err := connection.SetReadDeadline(time.Now()); err != nil {
			return err
		}
		<-done
		return connection.SetReadDeadline(time.Time{})
	}
	return ctx, cancel, stop
}

func writeMessage(connection net.Conn, message ipc.Message) error {
	if err := connection.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := ipc.WriteMessage(connection, message); err != nil {
		return err
	}
	return connection.SetWriteDeadline(time.Time{})
}
