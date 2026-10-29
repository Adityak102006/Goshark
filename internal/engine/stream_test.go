package engine

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"goshark/internal/capturefile"
	"goshark/internal/ipc"
)

func TestFollowTCPStreamReassemblesOutOfOrderTCPData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out-of-order.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := capturefile.WritePCAPHeader(file, 4096, layers.LinkTypeEthernet); err != nil {
		file.Close()
		t.Fatal(err)
	}
	clientIP := []byte{192, 0, 2, 10}
	serverIP := []byte{198, 51, 100, 20}
	packets := []struct {
		sourceIP      []byte
		destinationIP []byte
		sourcePort    layers.TCPPort
		destPort      layers.TCPPort
		sequence      uint32
		acknowledge   uint32
		syn           bool
		ack           bool
		payload       []byte
	}{
		{sourceIP: clientIP, destinationIP: serverIP, sourcePort: 41000, destPort: 80, sequence: 1000, syn: true},
		{sourceIP: serverIP, destinationIP: clientIP, sourcePort: 80, destPort: 41000, sequence: 9000, acknowledge: 1001, syn: true, ack: true},
		{sourceIP: clientIP, destinationIP: serverIP, sourcePort: 41000, destPort: 80, sequence: 1001, acknowledge: 9001, ack: true},
		{sourceIP: clientIP, destinationIP: serverIP, sourcePort: 41000, destPort: 80, sequence: 1007, acknowledge: 9001, ack: true, payload: []byte("world")},
		{sourceIP: clientIP, destinationIP: serverIP, sourcePort: 41000, destPort: 80, sequence: 1001, acknowledge: 9001, ack: true, payload: []byte("Hello ")},
		{sourceIP: serverIP, destinationIP: clientIP, sourcePort: 80, destPort: 41000, sequence: 9001, acknowledge: 1012, ack: true, payload: []byte("200 OK")},
	}
	for index, item := range packets {
		data := serializeStreamPacket(t, item.sourceIP, item.destinationIP, item.sourcePort, item.destPort, item.sequence, item.acknowledge, item.syn, item.ack, item.payload)
		packet := capturefile.Packet{Data: data, Timestamp: time.Unix(1700000000+int64(index), 0), Original: uint32(len(data)), LinkType: layers.LinkTypeEthernet}
		if err := capturefile.WritePCAPPacket(file, packet, 4096); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	request := ipc.Message{ID: 22, Type: "request", Operation: "follow_tcp_stream", Path: path, PacketNumber: 4}
	response, messages := invokeStream(t, &Server{}, request)
	if response.ClientBytes != uint32(len("Hello world")) || response.ServerBytes != uint32(len("200 OK")) || response.ClientGaps != 0 || response.ServerGaps != 0 {
		t.Fatalf("reassembled lengths = client %d server %d", response.ClientBytes, response.ServerBytes)
	}
	var clientData []byte
	var serverData []byte
	for _, message := range messages {
		switch message.StreamDirection {
		case "client":
			clientData = append(clientData, message.Data...)
		case "server":
			serverData = append(serverData, message.Data...)
		}
	}
	if string(clientData) != "Hello world" || string(serverData) != "200 OK" {
		t.Fatalf("reassembled stream data = client %q server %q", clientData, serverData)
	}
}

func serializeStreamPacket(t *testing.T, sourceIP, destinationIP []byte, sourcePort, destinationPort layers.TCPPort, sequence, acknowledge uint32, syn, ack bool, payload []byte) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: sourceIP, DstIP: destinationIP}
	tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: sequence, Ack: acknowledge, SYN: syn, ACK: ack, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func invokeStream(t *testing.T, server *Server, request ipc.Message) (ipc.Message, []ipc.Message) {
	t.Helper()
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	result := make(chan error, 1)
	go func() {
		result <- server.Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	response, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != "response" {
		t.Fatalf("stream metadata response = %#v", response)
	}
	messages := make([]ipc.Message, 0, 4)
	for {
		message, err := ipc.ReadMessage(clientSide)
		if err != nil {
			t.Fatal(err)
		}
		if message.Type == "end" {
			break
		}
		if message.Type != "batch" {
			t.Fatalf("stream message = %#v", message)
		}
		messages = append(messages, message)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return response, messages
}

func TestFollowTCPStreamReassemblesOfflineCapture(t *testing.T) {
	server := &Server{}
	engineSide, clientSide := net.Pipe()
	defer clientSide.Close()
	request := ipc.Message{ID: 21, Type: "request", Operation: "follow_tcp_stream", Path: "../../testdata/http.pcap", PacketNumber: 1}
	result := make(chan error, 1)
	go func() {
		result <- server.Handle(context.Background(), request, engineSide)
		engineSide.Close()
	}()
	response, err := ipc.ReadMessage(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != "response" || response.ClientAddress == "" || response.ServerAddress == "" || response.ClientPort == "" || response.ServerPort != "80" {
		t.Fatalf("stream metadata = %#v", response)
	}
	var clientBytes uint32
	var serverBytes uint32
	for {
		message, err := ipc.ReadMessage(clientSide)
		if err != nil {
			t.Fatal(err)
		}
		if message.Type == "end" {
			if message.Captured != uint64(response.ClientBytes+response.ServerBytes) {
				t.Fatalf("stream end counters = %#v", message)
			}
			break
		}
		if message.Type != "batch" || len(message.Data) > maxStreamChunkBytes {
			t.Fatalf("stream chunk = %#v", message)
		}
		if message.StreamDirection == "client" {
			clientBytes += uint32(len(message.Data))
		} else if message.StreamDirection == "server" {
			serverBytes += uint32(len(message.Data))
		} else {
			t.Fatalf("unknown stream direction %q", message.StreamDirection)
		}
	}
	if clientBytes != response.ClientBytes || serverBytes != response.ServerBytes || clientBytes == 0 {
		t.Fatalf("stream bytes differ from metadata: client %d/%d server %d/%d", clientBytes, response.ClientBytes, serverBytes, response.ServerBytes)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
