package dissection

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type ByteRange struct {
	Start  int
	Length int
}

type Field struct {
	Name  string
	Value string
	Bytes ByteRange
}

type Protocol struct {
	Name   string
	Start  int
	Length int
	Fields []Field
}

type Result struct {
	Protocols []Protocol
	Error     string
}

func Dissect(data []byte, linkType layers.LinkType) (result Result, err error) {
	defer func() {
		if recover() != nil {
			result = Result{}
			err = errors.New("packet dissection failed safely")
		}
	}()
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{NoCopy: true, Lazy: false, SkipDecodeRecovery: false, DecodeStreamsAsDatagrams: true})
	result.Protocols = make([]Protocol, 0, len(packet.Layers()))
	offset := 0
	informationElementOffset := -1
	for _, layer := range packet.Layers() {
		contents := layer.LayerContents()
		start := offset
		if layer.LayerType() == layers.LayerTypeDot11InformationElement && informationElementOffset >= 0 {
			start = informationElementOffset
			informationElementOffset += len(contents)
		} else {
			if offset > len(data) || len(contents) > len(data)-offset {
				return Result{}, errors.New("dissector returned a byte range outside the packet")
			}
			offset += len(contents)
			if prefix, ok := dot11InformationElementPrefix(layer); ok {
				if len(contents) < prefix {
					return Result{}, errors.New("dissector returned a truncated 802.11 management layer")
				}
				informationElementOffset = start + prefix
			}
		}
		if start < 0 || start > len(data) || len(contents) > len(data)-start {
			return Result{}, errors.New("dissector returned a byte range outside the packet")
		}
		protocol := Protocol{
			Name:   layer.LayerType().String(),
			Start:  start,
			Length: len(contents),
		}
		protocol.Fields = protocolFields(layer, start, contents)
		result.Protocols = append(result.Protocols, protocol)
	}
	if application := httpProtocol(data, result.Protocols); application != nil {
		result.Protocols = append(result.Protocols, *application)
	}
	if packet.ErrorLayer() != nil {
		result.Error = packet.ErrorLayer().Error().Error()
	}
	return result, nil
}

func protocolFields(layer gopacket.Layer, start int, contents []byte) []Field {
	fields := make([]Field, 0, 8)
	add := func(name, value string, offset, length int) {
		if offset < 0 || length < 0 || offset > len(contents) || length > len(contents)-offset {
			return
		}
		fields = append(fields, Field{
			Name:  name,
			Value: value,
			Bytes: ByteRange{Start: start + offset, Length: length},
		})
	}
	switch decoded := layer.(type) {
	case *layers.Dot11:
		add("Frame type", fmt.Sprint(decoded.Type), 0, 1)
		add("Flags", fmt.Sprint(decoded.Flags), 1, 1)
		add("Duration", fmt.Sprint(decoded.DurationID), 2, 2)
		add("Address 1", decoded.Address1.String(), 4, 6)
		add("Address 2", decoded.Address2.String(), 10, 6)
		add("Address 3", decoded.Address3.String(), 16, 6)
		add("Sequence number", fmt.Sprint(decoded.SequenceNumber), 22, 2)
	case *layers.Dot11MgmtBeacon:
		add("Timestamp", fmt.Sprint(decoded.Timestamp), 0, 8)
		add("Beacon interval", fmt.Sprint(decoded.Interval), 8, 2)
		add("Capabilities", fmt.Sprintf("0x%04x", decoded.Flags), 10, 2)
	case *layers.Dot11InformationElement:
		add("Element ID", decoded.ID.String(), 0, 1)
		add("Length", fmt.Sprint(decoded.Length), 1, 1)
		if len(decoded.Info) > 0 {
			add("Information", hex.EncodeToString(decoded.Info), 2, len(decoded.Info))
		}
	case *layers.Ethernet:
		add("Destination", decoded.DstMAC.String(), 0, 6)
		add("Source", decoded.SrcMAC.String(), 6, 6)
		add("Type", decoded.EthernetType.String(), 12, 2)
	case *layers.IPv4:
		add("Version", "4", 0, 1)
		add("Time to live", fmt.Sprint(decoded.TTL), 8, 1)
		add("Protocol", decoded.Protocol.String(), 9, 1)
		add("Source", decoded.SrcIP.String(), 12, 4)
		add("Destination", decoded.DstIP.String(), 16, 4)
	case *layers.IPv6:
		add("Version", "6", 0, 4)
		add("Next header", decoded.NextHeader.String(), 6, 1)
		add("Hop limit", fmt.Sprint(decoded.HopLimit), 7, 1)
		add("Source", decoded.SrcIP.String(), 8, 16)
		add("Destination", decoded.DstIP.String(), 24, 16)
	case *layers.TCP:
		add("Source port", fmt.Sprint(uint16(decoded.SrcPort)), 0, 2)
		add("Destination port", fmt.Sprint(uint16(decoded.DstPort)), 2, 2)
		add("Sequence number", fmt.Sprint(decoded.Seq), 4, 4)
		add("Acknowledgment number", fmt.Sprint(decoded.Ack), 8, 4)
		flags := make([]string, 0, 9)
		if decoded.FIN {
			flags = append(flags, "FIN")
		}
		if decoded.SYN {
			flags = append(flags, "SYN")
		}
		if decoded.RST {
			flags = append(flags, "RST")
		}
		if decoded.PSH {
			flags = append(flags, "PSH")
		}
		if decoded.ACK {
			flags = append(flags, "ACK")
		}
		if decoded.URG {
			flags = append(flags, "URG")
		}
		if decoded.ECE {
			flags = append(flags, "ECE")
		}
		if decoded.CWR {
			flags = append(flags, "CWR")
		}
		if decoded.NS {
			flags = append(flags, "NS")
		}
		add("Flags", strings.Join(flags, ", "), 13, 1)
	case *layers.TLS:
		recordNumber := 1
		for offset := 0; offset+5 <= len(contents); {
			contentType := layers.TLSType(contents[offset])
			version := layers.TLSVersion(binary.BigEndian.Uint16(contents[offset+1 : offset+3]))
			recordLength := int(binary.BigEndian.Uint16(contents[offset+3 : offset+5]))
			add(fmt.Sprintf("Record %d type", recordNumber), contentType.String(), offset, 1)
			add(fmt.Sprintf("Record %d version", recordNumber), version.String(), offset+1, 2)
			add(fmt.Sprintf("Record %d length", recordNumber), fmt.Sprint(recordLength), offset+3, 2)
			if recordLength > len(contents)-offset-5 {
				break
			}
			offset += 5 + recordLength
			recordNumber++
		}
	case *layers.DNS:
		messageType := "Query"
		if decoded.QR {
			messageType = "Response"
		}
		add("ID", fmt.Sprint(decoded.ID), 0, 2)
		add("Message type", messageType, 2, 1)
		add("Opcode", decoded.OpCode.String(), 2, 1)
		add("Response code", decoded.ResponseCode.String(), 3, 1)
		add("Question count", fmt.Sprint(decoded.QDCount), 4, 2)
		add("Answer count", fmt.Sprint(decoded.ANCount), 6, 2)
		add("Authority count", fmt.Sprint(decoded.NSCount), 8, 2)
		add("Additional count", fmt.Sprint(decoded.ARCount), 10, 2)
	case *layers.UDP:
		add("Source port", fmt.Sprint(uint16(decoded.SrcPort)), 0, 2)
		add("Destination port", fmt.Sprint(uint16(decoded.DstPort)), 2, 2)
		add("Length", fmt.Sprint(decoded.Length), 4, 2)
	case *layers.ARP:
		add("Operation", fmt.Sprint(decoded.Operation), 6, 2)
		hardwareLength := int(decoded.HwAddressSize)
		protocolLength := int(decoded.ProtAddressSize)
		senderProtocolOffset := 8 + hardwareLength
		targetHardwareOffset := senderProtocolOffset + protocolLength
		targetProtocolOffset := targetHardwareOffset + hardwareLength
		add("Sender hardware address", net.HardwareAddr(decoded.SourceHwAddress).String(), 8, hardwareLength)
		add("Sender protocol address", net.IP(decoded.SourceProtAddress).String(), senderProtocolOffset, protocolLength)
		add("Target hardware address", net.HardwareAddr(decoded.DstHwAddress).String(), targetHardwareOffset, hardwareLength)
		add("Target protocol address", net.IP(decoded.DstProtAddress).String(), targetProtocolOffset, protocolLength)
	}
	return fields
}
