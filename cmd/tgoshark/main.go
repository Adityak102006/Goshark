package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"goshark/internal/capture"
	"goshark/internal/capturefile"
	"goshark/internal/displayfilter"
	"goshark/internal/dissection"
)

type options struct {
	interfaces    bool
	readPath      string
	interfaceName string
	captureFilter string
	displayFilter string
	outputPath    string
	limit         int64
	snaplen       int
	promiscuous   bool
	verbose       bool
	hexDump       bool
}

type packetOutput struct {
	file     *capturefile.AtomicFile
	writer   *pcapgo.Writer
	linkType layers.LinkType
}

type packetPrinter struct {
	filter     *displayfilter.Filter
	output     *packetOutput
	outputPath string
	verbose    bool
	hexDump    bool
	seen       int64
	shown      int64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("tgoshark", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var selected options
	flags.BoolVar(&selected.interfaces, "interfaces", false, "list capture interfaces")
	flags.StringVar(&selected.readPath, "read", "", "read a capture file")
	flags.StringVar(&selected.interfaceName, "interface", "", "capture from an interface")
	flags.StringVar(&selected.captureFilter, "capture-filter", "", "capture filter compiled by libpcap")
	flags.StringVar(&selected.displayFilter, "display-filter", "", "goshark display filter")
	flags.StringVar(&selected.outputPath, "output", "", "write captured packets as pcap")
	flags.Int64Var(&selected.limit, "limit", 0, "stop after reading this many packets; zero is unlimited")
	flags.IntVar(&selected.snaplen, "snaplen", 262144, "maximum captured bytes per packet")
	flags.BoolVar(&selected.promiscuous, "promiscuous", false, "enable promiscuous capture")
	flags.BoolVar(&selected.verbose, "verbose", false, "print protocol fields")
	flags.BoolVar(&selected.hexDump, "hex", false, "print packet bytes as hex and ASCII")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tgoshark --interfaces | --read FILE | --interface NAME [options]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if selected.interfaces {
		interfaces, err := capture.ListInterfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			fmt.Printf("%s\t%s\t%s\n", safeText(iface.Name), safeText(iface.Description), strings.Join(iface.Addresses, ", "))
		}
		return nil
	}
	if selected.readPath != "" && selected.interfaceName != "" || selected.readPath == "" && selected.interfaceName == "" {
		return errors.New("choose exactly one of --read or --interface")
	}
	if selected.limit < 0 {
		return errors.New("packet limit must not be negative")
	}
	if _, err := checkedSnaplen(selected.snaplen); err != nil {
		return err
	}
	filter, err := displayfilter.Compile(selected.displayFilter)
	if err != nil {
		return err
	}
	printer := &packetPrinter{filter: filter, outputPath: selected.outputPath, verbose: selected.verbose, hexDump: selected.hexDump}
	if selected.outputPath != "" {
		printer.output = &packetOutput{}
	}
	if selected.readPath != "" {
		err = readCapture(selected, printer)
	} else {
		err = liveCapture(selected, printer)
	}
	closeErr := printer.closeOutput(err == nil)
	if err != nil {
		return errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Fprintf(os.Stderr, "Packets read: %d, displayed: %d\n", printer.seen, printer.shown)
	return nil
}

func readCapture(selected options, printer *packetPrinter) (runErr error) {
	reader, err := capturefile.OpenFile(selected.readPath, capturefile.DefaultLimits())
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, reader.Close())
	}()
	var packetBuffer []byte
	for {
		if selected.limit > 0 && printer.seen >= selected.limit {
			return nil
		}
		packet, err := reader.ReadPacketInto(packetBuffer)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read capture packet: %w", err)
		}
		packetBuffer = packet.Data
		if err := printer.process(packet); err != nil {
			return err
		}
	}
}

func checkedSnaplen(value int) (int32, error) {
	if value < 64 || int64(value) > int64(16<<20) {
		return 0, errors.New("snaplen must be between 64 bytes and 16 MiB")
	}
	return int32(value), nil
}

func liveCapture(selected options, printer *packetPrinter) error {
	snapshotLength, err := checkedSnaplen(selected.snaplen)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var handlerErr error
	stats, err := capture.Capture(ctx, capture.LiveOptions{
		Interface:      selected.interfaceName,
		SnapshotLength: snapshotLength,
		Promiscuous:    selected.promiscuous,
		CaptureFilter:  selected.captureFilter,
		ReadTimeout:    200 * time.Millisecond,
	}, func(packet capturefile.Packet) error {
		if handlerErr != nil {
			return handlerErr
		}
		handlerErr = printer.process(packet)
		if selected.limit > 0 && printer.seen >= selected.limit {
			cancel()
		}
		return handlerErr
	})
	if handlerErr != nil {
		return handlerErr
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	fmt.Fprintf(os.Stderr, "Capture received: %d, dropped: %d, interface dropped: %d\n", stats.Received, stats.Dropped, stats.InterfaceDrops)
	return nil
}

func (p *packetPrinter) process(packet capturefile.Packet) error {
	p.seen++
	if p.output != nil {
		if p.output.writer == nil {
			file, err := capturefile.NewAtomicFile(p.outputPath)
			if err != nil {
				return err
			}
			p.output.file = file
			p.output.writer = pcapgo.NewWriter(file.File())
			p.output.linkType = packet.LinkType
			if err := p.output.writer.WriteFileHeader(16<<20, packet.LinkType); err != nil {
				return fmt.Errorf("write pcap header: %w", err)
			}
		} else if p.output.linkType != packet.LinkType {
			return errors.New("pcap output cannot contain packets from different link types")
		}
		if err := p.output.writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     packet.Timestamp,
			CaptureLength: len(packet.Data),
			Length:        int(packet.Original),
		}, packet.Data); err != nil {
			return fmt.Errorf("write pcap packet: %w", err)
		}
	}
	if !p.filter.Match(packet.Data, packet.LinkType, packet.Original) {
		return nil
	}
	p.shown++
	result, err := dissection.Dissect(packet.Data, packet.LinkType)
	if err != nil {
		return err
	}
	protocolName := "Unknown"
	for index := len(result.Protocols) - 1; index >= 0; index-- {
		name := result.Protocols[index].Name
		if name != "Payload" && name != "Padding" && name != "Dot11InformationElement" {
			protocolName = name
			break
		}
	}
	fmt.Printf("%8d  %s  %-14s  %8d  %s\n", p.seen, packet.Timestamp.Format(time.RFC3339Nano), safeText(protocolName), len(packet.Data), packetSummary(result))
	if p.verbose {
		for _, protocol := range result.Protocols {
			fmt.Printf("  %s [%d..%d]\n", safeText(protocol.Name), protocol.Start, protocol.Start+protocol.Length)
			for _, field := range protocol.Fields {
				fmt.Printf("    %s: %s [%d..%d]\n", safeText(field.Name), safeText(field.Value), field.Bytes.Start, field.Bytes.Start+field.Bytes.Length)
			}
		}
		if result.Error != "" {
			fmt.Printf("  Decode error: %s\n", safeText(result.Error))
		}
	}
	if p.hexDump {
		printHex(packet.Data)
	}
	return nil
}

func (p *packetPrinter) closeOutput(commit bool) error {
	if p.output == nil || p.output.file == nil {
		return nil
	}
	var err error
	if commit {
		err = p.output.file.Commit()
	}
	return errors.Join(err, p.output.file.Close())
}

func packetSummary(result dissection.Result) string {
	source := ""
	destination := ""
	for _, protocol := range result.Protocols {
		for _, field := range protocol.Fields {
			switch {
			case field.Name == "Source" && source == "":
				source = field.Value
			case field.Name == "Destination" && destination == "":
				destination = field.Value
			case protocol.Name == "Dot11" && field.Name == "Address 2" && source == "":
				source = field.Value
			case protocol.Name == "Dot11" && field.Name == "Address 1" && destination == "":
				destination = field.Value
			}
		}
	}
	if source == "" || destination == "" {
		return ""
	}
	return safeText(source) + " → " + safeText(destination)
}

func printHex(data []byte) {
	for offset := 0; offset < len(data); offset += 16 {
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		var hexPart strings.Builder
		var asciiPart strings.Builder
		for index := offset; index < offset+16; index++ {
			if index < end {
				fmt.Fprintf(&hexPart, "%02x ", data[index])
				if data[index] >= 32 && data[index] <= 126 {
					asciiPart.WriteByte(data[index])
				} else {
					asciiPart.WriteByte('.')
				}
			} else {
				hexPart.WriteString("   ")
			}
		}
		fmt.Printf("    %08x  %s |%s|\n", offset, hexPart.String(), asciiPart.String())
	}
}

func safeText(value string) string {
	var safe strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == 0x1b {
			safe.WriteRune('?')
		} else {
			safe.WriteRune(character)
		}
	}
	return safe.String()
}
