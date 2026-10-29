package capture

import (
	"context"
	"testing"
	"time"

	"goshark/internal/capturefile"
)

func TestListInterfaces(t *testing.T) {
	interfaces, err := ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name == "" || seen[iface.Name] {
			t.Fatalf("invalid or duplicate interface name %q", iface.Name)
		}
		seen[iface.Name] = true
		t.Logf("interface name=%q description=%q addresses=%v", iface.Name, iface.Description, iface.Addresses)
	}
}

func TestCaptureRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		options LiveOptions
	}{
		{name: "missing interface", options: LiveOptions{SnapshotLength: 2048, ReadTimeout: 100 * time.Millisecond}},
		{name: "small snaplen", options: LiveOptions{Interface: "lo", SnapshotLength: 1, ReadTimeout: 100 * time.Millisecond}},
		{name: "nul filter", options: LiveOptions{Interface: "lo", SnapshotLength: 2048, CaptureFilter: "tcp\x00", ReadTimeout: 100 * time.Millisecond}},
		{name: "missing handler", options: LiveOptions{Interface: "lo", SnapshotLength: 2048, ReadTimeout: 100 * time.Millisecond}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var handler func(packet capturefile.Packet) error
			if test.name != "missing handler" {
				handler = func(capturefile.Packet) error { return nil }
			}
			_, err := Capture(context.Background(), test.options, handler)
			if err == nil {
				t.Fatal("Capture succeeded with invalid options")
			}
		})
	}
}
