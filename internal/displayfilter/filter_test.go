package displayfilter

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"goshark/internal/capturefile"
)

func TestSupportedGrammar(t *testing.T) {
	expressions := []string{
		"tcp",
		"tcp.port == 443",
		"udp && (ip.src == 192.0.2.1 || ip.dst != 198.51.100.1)",
		"!icmpv6",
		"frame.len >= 64",
		"ipv6.addr == 2001:db8::1",
		"!(ip.src == 192.0.2.1 && tcp.srcport == 12345 && ip.dst == 198.51.100.2 && tcp.dstport == 443) && !(ip.src == 198.51.100.2 && tcp.srcport == 443 && ip.dst == 192.0.2.1 && tcp.dstport == 12345)",
		"!(ipv6.src == 2001:db8::1 && tcp.srcport == 12345 && ipv6.dst == 2001:db8::2 && tcp.dstport == 443)",
	}
	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			if _, err := Compile(expression); err != nil {
				t.Fatalf("Compile(%q): %v", expression, err)
			}
		})
	}
}

func TestRejectedGrammarHasPosition(t *testing.T) {
	expressions := []string{
		"tcp.port = 443",
		"tcp.port == abc",
		"dns ||",
		"unknown.field == 1",
		"ip.src > 192.0.2.1",
		"frame.len == 4294967296",
		"tcp && (udp",
	}
	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			_, err := Compile(expression)
			if err == nil {
				t.Fatalf("Compile(%q) succeeded", expression)
			}
			var parseErr *ParseError
			if !errors.As(err, &parseErr) || parseErr.Position < 1 {
				t.Fatalf("error = %#v, want positioned ParseError", err)
			}
		})
	}
}

func TestFilterMatchesRealPCAP(t *testing.T) {
	input, err := os.Open("../../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, err := capturefile.NewReader(input, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := Compile("frame.len == 30")
	if err != nil {
		t.Fatal(err)
	}
	noMatch, err := Compile("tcp")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := reader.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !matches.Match(packet.Data, packet.LinkType, packet.Original) {
		t.Fatal("frame length filter did not match real packet")
	}
	if noMatch.Match(packet.Data, packet.LinkType, packet.Original) {
		t.Fatal("TCP filter unexpectedly matched real ARP fixture")
	}
}

func TestProtocolFilterMatchesRealTCPFixture(t *testing.T) {
	input, err := os.Open("../../testdata/http.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, err := capturefile.NewReader(input, capturefile.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	filter, err := Compile("tcp")
	if err != nil {
		t.Fatal(err)
	}
	for {
		packet, err := reader.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if filter.Match(packet.Data, packet.LinkType, packet.Original) {
			return
		}
	}
	t.Fatal("TCP filter did not match any frame in the real TCP fixture")
}

func TestEmptyFilterMatches(t *testing.T) {
	filter, err := Compile("")
	if err != nil {
		t.Fatal(err)
	}
	if !filter.Match(nil, layers.LinkTypeEthernet, 0) {
		t.Fatal("empty filter did not match")
	}
}

func FuzzDisplayFilter(f *testing.F) {
	f.Add("tcp.port == 443 && ip.src == 192.0.2.1")
	f.Add("dns || (udp && frame.len >= 64)")
	f.Add("tcp.port = 443")
	f.Fuzz(func(t *testing.T, expression string) {
		_, _ = Compile(expression)
	})
}

func FuzzDisplayFilterPacket(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{0xff, 0xff, 0xff})
	filter, err := Compile("tcp || udp || dns")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = filter.Match(data, layers.LinkTypeEthernet, uint32(len(data)))
	})
}
