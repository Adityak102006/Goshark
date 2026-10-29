package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	MaxMessageBytes   = 1 << 20
	MaxFramesPerBatch = 128
	MaxStringBytes    = 4096
)

type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

type Frame struct {
	Number          uint64 `json:"number"`
	Timestamp       string `json:"timestamp"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	SourcePort      string `json:"source_port"`
	DestinationPort string `json:"destination_port"`
	Protocol        string `json:"protocol"`
	Info            string `json:"info"`
	Length          uint32 `json:"length"`
	LinkType        uint16 `json:"link_type"`
}

type Field struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	ByteStart  uint32 `json:"byte_start"`
	ByteLength uint32 `json:"byte_length"`
}

type Protocol struct {
	Name       string  `json:"name"`
	ByteStart  uint32  `json:"byte_start"`
	ByteLength uint32  `json:"byte_length"`
	Fields     []Field `json:"fields"`
}

type Message struct {
	ID               uint64      `json:"id"`
	Type             string      `json:"type"`
	Operation        string      `json:"operation,omitempty"`
	Path             string      `json:"path,omitempty"`
	OutputPath       string      `json:"output_path,omitempty"`
	DisplayFilter    string      `json:"display_filter,omitempty"`
	InterfaceName    string      `json:"interface_name,omitempty"`
	CaptureFilter    string      `json:"capture_filter,omitempty"`
	Promiscuous      bool        `json:"promiscuous,omitempty"`
	Limit            uint32      `json:"limit,omitempty"`
	PacketNumber     uint64      `json:"packet_number,omitempty"`
	ByteOffset       uint32      `json:"byte_offset,omitempty"`
	ByteLength       uint32      `json:"byte_length,omitempty"`
	TotalBytes       uint32      `json:"total_bytes,omitempty"`
	More             bool        `json:"more,omitempty"`
	Error            string      `json:"error,omitempty"`
	Format           string      `json:"format,omitempty"`
	CaptureInterface string      `json:"capture_interface,omitempty"`
	CaptureID        string      `json:"capture_id,omitempty"`
	StreamDirection  string      `json:"stream_direction,omitempty"`
	StreamTimestamp  string      `json:"stream_timestamp,omitempty"`
	StreamOffset     uint32      `json:"stream_offset,omitempty"`
	StreamTotal      uint32      `json:"stream_total,omitempty"`
	ClientAddress    string      `json:"client_address,omitempty"`
	ServerAddress    string      `json:"server_address,omitempty"`
	ClientPort       string      `json:"client_port,omitempty"`
	ServerPort       string      `json:"server_port,omitempty"`
	ClientBytes      uint32      `json:"client_bytes,omitempty"`
	ServerBytes      uint32      `json:"server_bytes,omitempty"`
	ClientGaps       uint32      `json:"client_gaps,omitempty"`
	ServerGaps       uint32      `json:"server_gaps,omitempty"`
	Truncated        bool        `json:"truncated,omitempty"`
	Captured         uint64      `json:"captured,omitempty"`
	Displayed        uint64      `json:"displayed,omitempty"`
	Dropped          uint64      `json:"dropped,omitempty"`
	Interfaces       []Interface `json:"interfaces,omitempty"`
	Frames           []Frame     `json:"frames,omitempty"`
	Protocols        []Protocol  `json:"protocols,omitempty"`
	Data             []byte      `json:"data,omitempty"`
}

func ReadMessage(reader io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Message{}, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxMessageBytes {
		return Message{}, fmt.Errorf("invalid IPC message length %d", length)
	}
	encoded := make([]byte, int(length))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return Message{}, fmt.Errorf("read IPC message: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var message Message
	if err := decoder.Decode(&message); err != nil {
		return Message{}, fmt.Errorf("decode IPC message: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Message{}, errors.New("IPC message contains trailing JSON data")
	}
	if err := Validate(message); err != nil {
		return Message{}, err
	}
	return message, nil
}

func WriteMessage(writer io.Writer, message Message) error {
	if err := Validate(message); err != nil {
		return err
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode IPC message: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxMessageBytes {
		return fmt.Errorf("IPC message size %d exceeds limit", len(encoded))
	}
	length, err := messageLength(len(encoded))
	if err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], length)
	if err := writeAll(writer, header[:]); err != nil {
		return fmt.Errorf("write IPC length prefix: %w", err)
	}
	if err := writeAll(writer, encoded); err != nil {
		return fmt.Errorf("write IPC message: %w", err)
	}
	return nil
}

func Validate(message Message) error {
	if message.ID == 0 {
		return errors.New("IPC message id must be positive")
	}
	switch message.Type {
	case "request":
		if message.Error != "" || len(message.Frames) > 0 || len(message.Interfaces) > 0 || len(message.Protocols) > 0 || len(message.Data) > 0 {
			return errors.New("IPC request contains response-only fields")
		}
		switch message.Operation {
		case "list_interfaces":
		case "open_capture":
			if message.Path == "" || len(message.Path) > MaxStringBytes {
				return errors.New("capture path is empty or too long")
			}
			if len(message.DisplayFilter) > MaxStringBytes {
				return errors.New("display filter is too long")
			}
		case "save_capture":
			if message.OutputPath == "" || len(message.OutputPath) > MaxStringBytes || len(message.DisplayFilter) > MaxStringBytes {
				return errors.New("capture export has an invalid output path or filter")
			}
			if message.CaptureID == "" && (message.Path == "" || len(message.Path) > MaxStringBytes) {
				return errors.New("offline capture export is missing a valid source path")
			}
			if message.CaptureID != "" && (len(message.CaptureID) > 64 || message.Path != "") {
				return errors.New("live capture export has an invalid capture id or an unexpected path")
			}
		case "packet_detail", "packet_bytes":
			if message.PacketNumber == 0 {
				return errors.New("packet detail request is missing a packet number")
			}
			if message.CaptureID == "" && (message.Path == "" || len(message.Path) > MaxStringBytes) {
				return errors.New("offline packet detail request is missing a valid path")
			}
			if message.CaptureID != "" && (len(message.CaptureID) > 64 || message.Path != "") {
				return errors.New("live packet detail request has an invalid capture id or an unexpected path")
			}
			if message.Operation == "packet_bytes" && (message.ByteLength == 0 || message.ByteLength > 65536) {
				return errors.New("packet byte request length must be between 1 and 65536")
			}
		case "follow_tcp_stream":
			if message.Path == "" || len(message.Path) > MaxStringBytes || message.PacketNumber == 0 {
				return errors.New("TCP stream request is missing a valid path or packet number")
			}
		case "start_capture":
			if message.InterfaceName == "" || len(message.InterfaceName) > 512 || len(message.CaptureFilter) > MaxStringBytes || len(message.DisplayFilter) > MaxStringBytes {
				return errors.New("capture request has an invalid interface or filter")
			}
		default:
			return errors.New("unsupported IPC request operation")
		}
	case "response", "batch", "end", "error":
		if message.Operation != "" {
			return errors.New("IPC response must not contain a request operation")
		}
		if len(message.Frames) > MaxFramesPerBatch {
			return errors.New("IPC response contains too many packet rows")
		}
		if len(message.Error) > MaxStringBytes {
			return errors.New("IPC error text is too long")
		}
		if len(message.Interfaces) > 1024 || len(message.Protocols) > 256 || len(message.Data) > MaxMessageBytes/2 {
			return errors.New("IPC response exceeds a schema limit")
		}
		if len(message.CaptureID) > 64 || len(message.StreamDirection) > 16 || len(message.StreamTimestamp) > 64 || len(message.ClientAddress) > 256 || len(message.ServerAddress) > 256 || len(message.ClientPort) > 8 || len(message.ServerPort) > 8 {
			return errors.New("IPC stream metadata contains oversized text")
		}
		for _, frame := range message.Frames {
			if len(frame.Timestamp) > 64 || len(frame.Source) > 256 || len(frame.Destination) > 256 || len(frame.SourcePort) > 8 || len(frame.DestinationPort) > 8 || len(frame.Protocol) > 128 || len(frame.Info) > 512 {
				return errors.New("IPC packet row contains oversized text")
			}
		}
		for _, protocol := range message.Protocols {
			if len(protocol.Name) > 128 || len(protocol.Fields) > 512 {
				return errors.New("IPC protocol tree exceeds a schema limit")
			}
			for _, field := range protocol.Fields {
				if len(field.Name) > 128 || len(field.Value) > 1024 {
					return errors.New("IPC field text exceeds a schema limit")
				}
			}
		}
	default:
		return errors.New("unsupported IPC message type")
	}
	if strings.IndexByte(message.Path, 0) >= 0 || strings.IndexByte(message.OutputPath, 0) >= 0 || strings.IndexByte(message.CaptureID, 0) >= 0 || strings.IndexByte(message.InterfaceName, 0) >= 0 || strings.IndexByte(message.DisplayFilter, 0) >= 0 || strings.IndexByte(message.CaptureFilter, 0) >= 0 || strings.IndexByte(message.StreamDirection, 0) >= 0 || strings.IndexByte(message.ClientAddress, 0) >= 0 || strings.IndexByte(message.ServerAddress, 0) >= 0 || strings.IndexByte(message.ClientPort, 0) >= 0 || strings.IndexByte(message.ServerPort, 0) >= 0 {
		return errors.New("IPC text fields must not contain NUL bytes")
	}
	return nil
}

func messageLength(length int) (uint32, error) {
	if length < 1 || int64(length) > int64(MaxMessageBytes) {
		return 0, errors.New("IPC message length is outside the supported range")
	}
	return uint32(length), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
