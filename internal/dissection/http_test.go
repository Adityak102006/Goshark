package dissection

import (
	"testing"
)

func TestHTTPResponseFieldsAndByteRanges(t *testing.T) {
	data := []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n")
	protocol := httpProtocol(data, []Protocol{{Name: "Payload", Start: 0, Length: len(data)}})
	if protocol == nil || protocol.Name != "HTTP" {
		t.Fatal("HTTP response was not recognized")
	}
	fields := make(map[string]Field, len(protocol.Fields))
	for _, field := range protocol.Fields {
		fields[field.Name] = field
	}
	if fields["Status"].Value != "404" || fields["Status phrase"].Value != "Not Found" || fields["Content-Type"].Value != "text/plain" {
		t.Fatalf("HTTP response fields = %#v", fields)
	}
	for _, field := range fields {
		if field.Bytes.Start < 0 || field.Bytes.Start > len(data) || field.Bytes.Length < 0 || field.Bytes.Length > len(data)-field.Bytes.Start {
			t.Fatalf("invalid HTTP field range: %#v", field)
		}
	}
}

func TestHTTPRequestOffsetsSupportRepeatedWhitespace(t *testing.T) {
	data := []byte("GET  /safe/path   HTTP/1.1\r\nHost:\texample.test\r\n\r\n")
	protocol := httpProtocol(data, []Protocol{{Name: "Payload", Start: 0, Length: len(data)}})
	if protocol == nil {
		t.Fatal("HTTP request was not recognized")
	}
	fields := make(map[string]Field, len(protocol.Fields))
	for _, field := range protocol.Fields {
		fields[field.Name] = field
	}
	uri := fields["Request URI"]
	if uri.Value != "/safe/path" || string(data[uri.Bytes.Start:uri.Bytes.Start+uri.Bytes.Length]) != uri.Value {
		t.Fatalf("request URI range = %#v", uri)
	}
	host := fields["Host"]
	if host.Value != "example.test" || string(data[host.Bytes.Start:host.Bytes.Start+host.Bytes.Length]) != host.Value {
		t.Fatalf("host range = %#v", host)
	}
}
