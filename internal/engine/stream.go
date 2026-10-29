package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/tcpassembly"

	"goshark/internal/capturefile"
	"goshark/internal/ipc"
)

const (
	maxStreamBytes      = 8 << 20
	maxStreamChunkBytes = 32 << 10
	maxStreamBuffered   = 4096
	maxStreamSegments   = 65536
)

type streamFlowKey struct {
	network   gopacket.Flow
	transport gopacket.Flow
}

type streamSegment struct {
	order     uint64
	timestamp time.Time
	data      []byte
}

type orderedSegment struct {
	direction string
	segment   streamSegment
}

type streamDirection struct {
	segments  []streamSegment
	bytes     uint32
	gaps      uint32
	truncated bool
}

type streamCapture struct {
	targetNetwork   gopacket.Flow
	targetTransport gopacket.Flow
	streams         map[streamFlowKey]*streamDirection
	initiated       bool
	nextOrder       uint64
	clientNetwork   gopacket.Flow
	clientTransport gopacket.Flow
}

type reassembledStream struct {
	capture *streamCapture
	flow    streamFlowKey
}

func (s *Server) followTCPStream(ctx context.Context, request ipc.Message, connection net.Conn) (runErr error) {
	streamContext, _, stopWatching := watchClient(ctx, connection)
	defer func() {
		runErr = errors.Join(runErr, stopWatching())
	}()
	networkFlow, transportFlow, err := findTCPFlows(streamContext, request.Path, request.PacketNumber)
	if err != nil {
		return err
	}
	collector := &streamCapture{
		targetNetwork:   networkFlow,
		targetTransport: transportFlow,
		streams:         make(map[streamFlowKey]*streamDirection, 2),
	}
	pool := tcpassembly.NewStreamPool(collector)
	assembler := tcpassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = maxStreamBuffered
	assembler.MaxBufferedPagesTotal = maxStreamBuffered
	reader, err := capturefile.OpenFile(request.Path, capturefile.DefaultLimits())
	if err != nil {
		return err
	}
	var packetData []byte
	for {
		if streamContext.Err() != nil {
			return errors.Join(streamContext.Err(), reader.Close())
		}
		packet, readErr := reader.ReadPacketInto(packetData)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.Join(fmt.Errorf("read capture packet for TCP stream: %w", readErr), reader.Close())
		}
		packetData = packet.Data
		network, tcp := decodeTCP(packet.Data, packet.LinkType)
		if network == nil || tcp == nil {
			continue
		}
		netFlow := network.NetworkFlow()
		tcpFlow := tcp.TransportFlow()
		if !sameFlowPair(netFlow, tcpFlow, networkFlow, transportFlow) {
			continue
		}
		if !collector.initiated && tcp.SYN && !tcp.ACK {
			collector.initiated = true
			collector.clientNetwork = netFlow
			collector.clientTransport = tcpFlow
		}
		assembler.AssembleWithTimestamp(netFlow, tcp, packet.Timestamp)
	}
	if err := reader.Close(); err != nil {
		return fmt.Errorf("close capture after TCP stream read: %w", err)
	}
	assembler.FlushAll()
	if streamContext.Err() != nil {
		return streamContext.Err()
	}
	clientNetwork, clientTransport := networkFlow, transportFlow
	if collector.initiated {
		clientNetwork, clientTransport = collector.clientNetwork, collector.clientTransport
	}
	clientKey := streamFlowKey{network: clientNetwork, transport: clientTransport}
	serverKey := streamFlowKey{network: clientNetwork.Reverse(), transport: clientTransport.Reverse()}
	client := collector.streams[clientKey]
	server := collector.streams[serverKey]
	if client == nil {
		client = &streamDirection{}
	}
	if server == nil {
		server = &streamDirection{}
	}
	if err := writeMessage(connection, ipc.Message{
		ID:            request.ID,
		Type:          "response",
		ClientAddress: safeText(clientNetwork.Src().String()),
		ServerAddress: safeText(clientNetwork.Dst().String()),
		ClientPort:    portString(clientTransport.Src()),
		ServerPort:    portString(clientTransport.Dst()),
		ClientBytes:   client.bytes,
		ServerBytes:   server.bytes,
		ClientGaps:    client.gaps,
		ServerGaps:    server.gaps,
		Truncated:     client.truncated || server.truncated,
	}); err != nil {
		return err
	}
	segments := make([]orderedSegment, 0, len(client.segments)+len(server.segments))
	for _, segment := range client.segments {
		segments = append(segments, orderedSegment{direction: "client", segment: segment})
	}
	for _, segment := range server.segments {
		segments = append(segments, orderedSegment{direction: "server", segment: segment})
	}
	sort.SliceStable(segments, func(i, j int) bool {
		return segments[i].segment.order < segments[j].segment.order
	})
	var clientOffset uint32
	var serverOffset uint32
	for _, item := range segments {
		if streamContext.Err() != nil {
			return streamContext.Err()
		}
		for offset := 0; offset < len(item.segment.data); {
			end := min(offset+maxStreamChunkBytes, len(item.segment.data))
			message := ipc.Message{
				ID:              request.ID,
				Type:            "batch",
				StreamDirection: item.direction,
				StreamTimestamp: item.segment.timestamp.UTC().Format(time.RFC3339Nano),
				Data:            item.segment.data[offset:end],
			}
			chunkLength, err := intToUint32(end - offset)
			if err != nil {
				return err
			}
			if item.direction == "client" {
				message.StreamOffset = clientOffset
				message.StreamTotal = client.bytes
				clientOffset, err = addUint32(clientOffset, chunkLength)
			} else {
				message.StreamOffset = serverOffset
				message.StreamTotal = server.bytes
				serverOffset, err = addUint32(serverOffset, chunkLength)
			}
			if err != nil {
				return err
			}
			if err := writeMessage(connection, message); err != nil {
				return err
			}
			offset = end
		}
	}
	return writeMessage(connection, ipc.Message{ID: request.ID, Type: "end", Captured: uint64(clientOffset + serverOffset), Displayed: uint64(len(segments))})
}

func findTCPFlows(ctx context.Context, path string, packetNumber uint64) (gopacket.Flow, gopacket.Flow, error) {
	reader, err := capturefile.OpenFile(path, capturefile.DefaultLimits())
	if err != nil {
		return gopacket.Flow{}, gopacket.Flow{}, err
	}
	defer reader.Close()
	var packetData []byte
	for number := uint64(1); number <= packetNumber; number++ {
		if err := ctx.Err(); err != nil {
			return gopacket.Flow{}, gopacket.Flow{}, err
		}
		packet, err := reader.ReadPacketInto(packetData)
		if err != nil {
			return gopacket.Flow{}, gopacket.Flow{}, fmt.Errorf("read packet %d for TCP stream: %w", number, err)
		}
		packetData = packet.Data
		if number != packetNumber {
			continue
		}
		network, tcp := decodeTCP(packet.Data, packet.LinkType)
		if network == nil || tcp == nil {
			return gopacket.Flow{}, gopacket.Flow{}, errors.New("selected packet is not a TCP packet")
		}
		return network.NetworkFlow(), tcp.TransportFlow(), nil
	}
	return gopacket.Flow{}, gopacket.Flow{}, errors.New("selected packet number is outside the capture")
}

func decodeTCP(data []byte, linkType layers.LinkType) (gopacket.NetworkLayer, *layers.TCP) {
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{NoCopy: true, Lazy: false, SkipDecodeRecovery: false})
	network := packet.NetworkLayer()
	layer := packet.Layer(layers.LayerTypeTCP)
	if network == nil || layer == nil {
		return nil, nil
	}
	tcp, ok := layer.(*layers.TCP)
	if !ok {
		return nil, nil
	}
	return network, tcp
}

func sameFlowPair(network, transport, targetNetwork, targetTransport gopacket.Flow) bool {
	return network == targetNetwork && transport == targetTransport ||
		network == targetNetwork.Reverse() && transport == targetTransport.Reverse()
}

func (capture *streamCapture) New(network, transport gopacket.Flow) tcpassembly.Stream {
	if !sameFlowPair(network, transport, capture.targetNetwork, capture.targetTransport) {
		return &discardStream{}
	}
	key := streamFlowKey{network: network, transport: transport}
	direction := capture.streams[key]
	if direction == nil {
		direction = &streamDirection{}
		capture.streams[key] = direction
	}
	return &reassembledStream{capture: capture, flow: key}
}

func (stream *reassembledStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	direction := stream.capture.streams[stream.flow]
	for _, reassembly := range reassemblies {
		if reassembly.Skip != 0 && direction.gaps < ^uint32(0) {
			direction.gaps++
		}
		if len(reassembly.Bytes) == 0 {
			continue
		}
		remaining := maxStreamBytes - int(direction.bytes)
		if remaining <= 0 {
			direction.truncated = true
			continue
		}
		data := reassembly.Bytes
		if len(data) > remaining {
			data = data[:remaining]
			direction.truncated = true
		}
		if len(direction.segments) >= maxStreamSegments {
			direction.truncated = true
			continue
		}
		copyOfData := append([]byte(nil), data...)
		segmentLength, err := intToUint32(len(copyOfData))
		if err != nil || segmentLength > ^uint32(0)-direction.bytes {
			direction.truncated = true
			continue
		}
		stream.capture.nextOrder++
		direction.segments = append(direction.segments, streamSegment{order: stream.capture.nextOrder, timestamp: reassembly.Seen, data: copyOfData})
		direction.bytes += segmentLength
	}
}

func (stream *reassembledStream) ReassemblyComplete() {}

func (stream *discardStream) Reassembled([]tcpassembly.Reassembly) {}

func (stream *discardStream) ReassemblyComplete() {}

type discardStream struct{}

func addUint32(left, right uint32) (uint32, error) {
	if right > ^uint32(0)-left {
		return 0, errors.New("TCP stream byte offset exceeds the IPC numeric range")
	}
	return left + right, nil
}

func portString(endpoint gopacket.Endpoint) string {
	raw := endpoint.Raw()
	if len(raw) != 2 {
		return ""
	}
	return strconv.Itoa(int(binary.BigEndian.Uint16(raw)))
}
