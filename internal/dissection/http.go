package dissection

import (
	"bytes"
	"strings"
)

func httpProtocol(data []byte, protocols []Protocol) *Protocol {
	var payload *Protocol
	for index := len(protocols) - 1; index >= 0; index-- {
		if protocols[index].Name == "Payload" {
			payload = &protocols[index]
			break
		}
	}
	if payload == nil || payload.Start < 0 || payload.Length < 1 || payload.Start > len(data) || payload.Length > len(data)-payload.Start {
		return nil
	}
	contents := data[payload.Start : payload.Start+payload.Length]
	limit := min(len(contents), 64<<10)
	contents = contents[:limit]
	lineEnd := bytes.Index(contents, []byte("\r\n"))
	if lineEnd < 0 || lineEnd > 8192 {
		return nil
	}
	line := contents[:lineEnd]
	tokens := httpTokens(line)
	if len(tokens) < 2 {
		return nil
	}
	protocol := &Protocol{Name: "HTTP", Start: payload.Start, Length: payload.Length, Fields: make([]Field, 0, 6)}
	appendField := func(name, value string, start, length int) {
		if len(value) > 1024 {
			value = value[:1024]
		}
		protocol.Fields = append(protocol.Fields, Field{Name: name, Value: cleanHTTPText(value), Bytes: ByteRange{Start: start, Length: length}})
	}
	if strings.HasPrefix(tokens[0].value, "HTTP/") {
		appendField("Version", tokens[0].value, payload.Start+tokens[0].start, tokens[0].end-tokens[0].start)
		appendField("Status", tokens[1].value, payload.Start+tokens[1].start, tokens[1].end-tokens[1].start)
		phraseOffset := tokens[1].end
		for phraseOffset < len(line) && (line[phraseOffset] == ' ' || line[phraseOffset] == '\t') {
			phraseOffset++
		}
		if phraseOffset < len(line) {
			appendField("Status phrase", string(line[phraseOffset:]), payload.Start+phraseOffset, len(line)-phraseOffset)
		}
	} else if len(tokens) == 3 && strings.HasPrefix(tokens[2].value, "HTTP/") && validHTTPMethod(tokens[0].value) {
		appendField("Method", tokens[0].value, payload.Start+tokens[0].start, tokens[0].end-tokens[0].start)
		appendField("Request URI", tokens[1].value, payload.Start+tokens[1].start, tokens[1].end-tokens[1].start)
		appendField("Version", tokens[2].value, payload.Start+tokens[2].start, tokens[2].end-tokens[2].start)
	} else {
		return nil
	}
	lineOffset := lineEnd + 2
	for lineOffset < len(contents) {
		relativeEnd := bytes.Index(contents[lineOffset:], []byte("\r\n"))
		if relativeEnd < 0 || relativeEnd == 0 {
			break
		}
		header := contents[lineOffset : lineOffset+relativeEnd]
		colon := bytes.IndexByte(header, ':')
		if colon > 0 {
			name := strings.ToLower(string(header[:colon]))
			valueOffset := colon + 1
			for valueOffset < len(header) && (header[valueOffset] == ' ' || header[valueOffset] == '\t') {
				valueOffset++
			}
			fieldName := ""
			switch name {
			case "host":
				fieldName = "Host"
			case "user-agent":
				fieldName = "User-Agent"
			case "content-type":
				fieldName = "Content-Type"
			}
			if fieldName != "" {
				value := header[valueOffset:]
				appendField(fieldName, string(value), payload.Start+lineOffset+valueOffset, len(value))
			}
		}
		lineOffset += relativeEnd + 2
	}
	return protocol
}

func validHTTPMethod(method string) bool {
	if method == "" || len(method) > 32 {
		return false
	}
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func cleanHTTPText(value string) string {
	var result strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			result.WriteByte('?')
		} else {
			result.WriteRune(character)
		}
	}
	return result.String()
}

type httpToken struct {
	value string
	start int
	end   int
}

func httpTokens(line []byte) []httpToken {
	tokens := make([]httpToken, 0, 4)
	for offset := 0; offset < len(line); {
		for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
			offset++
		}
		if offset == len(line) {
			break
		}
		start := offset
		for offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
			offset++
		}
		tokens = append(tokens, httpToken{value: string(line[start:offset]), start: start, end: offset})
	}
	return tokens
}
