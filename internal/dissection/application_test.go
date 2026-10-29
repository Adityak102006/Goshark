package dissection

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDissectUDPHeaderFields(t *testing.T) {
	packet := serializeTransportPacket(t, layers.IPProtocolUDP, 12345, 5353, []byte{1, 2, 3, 4})
	result, err := Dissect(packet, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	fields := fieldsByProtocol(result, "UDP")
	if fields["Source port"].Value != "12345" || fields["Destination port"].Value != "5353" {
		t.Fatalf("UDP fields = %#v", fields)
	}
	if fields["Destination port"].Bytes.Start != 36 || fields["Destination port"].Bytes.Length != 2 {
		t.Fatalf("UDP byte range = %#v", fields["Destination port"].Bytes)
	}
}

func TestDissectDNSHeaderFields(t *testing.T) {
	dns := make([]byte, 12+17)
	binary.BigEndian.PutUint16(dns[0:2], 0x1234)
	binary.BigEndian.PutUint16(dns[2:4], 0x0100)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	copy(dns[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1})
	packet := serializeTransportPacket(t, layers.IPProtocolUDP, 53000, 53, dns)
	result, err := Dissect(packet, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	fields := fieldsByProtocol(result, "DNS")
	if fields["ID"].Value != "4660" || fields["Message type"].Value != "Query" || fields["Question count"].Value != "1" {
		t.Fatalf("DNS header fields = %#v", fields)
	}
	if fields["ID"].Bytes.Start != 42 || fields["ID"].Bytes.Length != 2 {
		t.Fatalf("DNS ID byte range = %#v", fields["ID"].Bytes)
	}
}

func TestDissectTLSRecordMetadataWithoutDecryption(t *testing.T) {
	tlsRecord := []byte{byte(layers.TLSApplicationData), 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc}
	packet := serializeTransportPacket(t, layers.IPProtocolTCP, 50000, 443, tlsRecord)
	result, err := Dissect(packet, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	fields := fieldsByProtocol(result, "TLS")
	if fields["Record 1 type"].Value != "Application Data" || fields["Record 1 version"].Value != "TLS 1.2" || fields["Record 1 length"].Value != "3" {
		t.Fatalf("TLS record fields = %#v", fields)
	}
	if fields["Record 1 type"].Bytes.Start != 54 || fields["Record 1 type"].Bytes.Length != 1 {
		t.Fatalf("TLS content-type byte range = %#v", fields["Record 1 type"].Bytes)
	}
}

func serializeTransportPacket(t *testing.T, protocol layers.IPProtocol, sourcePort, destinationPort layers.TCPPort, payload []byte) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: protocol,
		SrcIP:    []byte{192, 0, 2, 1},
		DstIP:    []byte{198, 51, 100, 2},
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if protocol == layers.IPProtocolTCP {
		tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: 1, Window: 65535}
		tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
	} else {
		udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, udp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func fieldsByProtocol(result Result, name string) map[string]Field {
	for _, protocol := range result.Protocols {
		if protocol.Name != name {
			continue
		}
		fields := make(map[string]Field, len(protocol.Fields))
		for _, field := range protocol.Fields {
			fields[field.Name] = field
		}
		return fields
	}
	return map[string]Field{}
}
