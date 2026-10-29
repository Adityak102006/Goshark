package displayfilter

import (
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type ParseError struct {
	Message  string
	Position int
}

func (e *ParseError) Error() string {
	return e.Message + " at position " + strconv.Itoa(e.Position)
}

type Filter struct {
	root *node
}

type tokenKind uint8

const (
	tokenWord tokenKind = iota + 1
	tokenAnd
	tokenOr
	tokenEqual
	tokenNotEqual
	tokenGreater
	tokenGreaterEqual
	tokenLess
	tokenLessEqual
	tokenNot
	tokenOpen
	tokenClose
)

type token struct {
	kind     tokenKind
	text     string
	position int
}

type nodeKind uint8

const (
	nodeProtocol nodeKind = iota + 1
	nodeComparison
	nodeNot
	nodeAnd
	nodeOr
)

type node struct {
	kind      nodeKind
	protocol  string
	field     string
	operator  tokenKind
	textValue string
	number    uint32
	address   net.IP
	left      *node
	right     *node
}

type parser struct {
	tokens []token
	index  int
	depth  int
}

type packetInfo struct {
	protocols map[string]bool
	ipv4Src   net.IP
	ipv4Dst   net.IP
	ipv6Src   net.IP
	ipv6Dst   net.IP
	tcpSrc    uint32
	tcpDst    uint32
	udpSrc    uint32
	udpDst    uint32
	length    uint32
}

func Compile(expression string) (*Filter, error) {
	if len(expression) > 4096 {
		return nil, &ParseError{Message: "filter exceeds 4096 bytes", Position: 4097}
	}
	if strings.TrimSpace(expression) == "" {
		return &Filter{}, nil
	}
	tokens, err := lex(expression)
	if err != nil {
		return nil, err
	}
	p := parser{tokens: tokens}
	root, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if p.index != len(p.tokens) {
		return nil, parseError("unexpected token "+p.tokens[p.index].text, p.tokens[p.index].position)
	}
	return &Filter{root: root}, nil
}

func SupportedFields() []string {
	return []string{
		"frame.len",
		"ip.src", "ip.dst", "ip.addr",
		"ipv6.src", "ipv6.dst", "ipv6.addr",
		"tcp.port", "tcp.srcport", "tcp.dstport",
		"udp.port", "udp.srcport", "udp.dstport",
	}
}

func SupportedProtocols() []string {
	return []string{"ip", "ipv6", "tcp", "udp", "dns", "icmp", "icmpv6"}
}

func (f *Filter) Match(data []byte, linkType layers.LinkType, originalLength uint32) (matched bool) {
	if f == nil || f.root == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()
	info := decode(data, linkType, originalLength)
	return f.root.evaluate(info)
}

func decode(data []byte, linkType layers.LinkType, originalLength uint32) packetInfo {
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{NoCopy: true, Lazy: false, SkipDecodeRecovery: false})
	info := packetInfo{protocols: make(map[string]bool), length: originalLength}
	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			info.protocols["ip"] = true
			if ip, ok := layer.(*layers.IPv4); ok {
				info.ipv4Src = append(net.IP(nil), ip.SrcIP...)
				info.ipv4Dst = append(net.IP(nil), ip.DstIP...)
			}
		case layers.LayerTypeIPv6:
			info.protocols["ipv6"] = true
			if ip, ok := layer.(*layers.IPv6); ok {
				info.ipv6Src = append(net.IP(nil), ip.SrcIP...)
				info.ipv6Dst = append(net.IP(nil), ip.DstIP...)
			}
		case layers.LayerTypeTCP:
			info.protocols["tcp"] = true
			if tcp, ok := layer.(*layers.TCP); ok {
				info.tcpSrc = uint32(tcp.SrcPort)
				info.tcpDst = uint32(tcp.DstPort)
			}
		case layers.LayerTypeUDP:
			info.protocols["udp"] = true
			if udp, ok := layer.(*layers.UDP); ok {
				info.udpSrc = uint32(udp.SrcPort)
				info.udpDst = uint32(udp.DstPort)
			}
		case layers.LayerTypeDNS:
			info.protocols["dns"] = true
		case layers.LayerTypeICMPv4:
			info.protocols["icmp"] = true
		case layers.LayerTypeICMPv6:
			info.protocols["icmpv6"] = true
		}
	}
	return info
}

func lex(expression string) ([]token, error) {
	tokens := make([]token, 0, len(expression)/2)
	for index := 0; index < len(expression); {
		character := expression[index]
		if character >= 0x80 {
			return nil, parseError("non-ASCII character is not allowed", index+1)
		}
		if unicode.IsSpace(rune(character)) {
			index++
			continue
		}
		start := index
		var kind tokenKind
		var width int
		switch character {
		case '&':
			kind, width = tokenAnd, 2
		case '|':
			kind, width = tokenOr, 2
		case '=':
			kind, width = tokenEqual, 2
		case '!':
			if index+1 < len(expression) && expression[index+1] == '=' {
				kind, width = tokenNotEqual, 2
			} else {
				kind, width = tokenNot, 1
			}
		case '>':
			if index+1 < len(expression) && expression[index+1] == '=' {
				kind, width = tokenGreaterEqual, 2
			} else {
				kind, width = tokenGreater, 1
			}
		case '<':
			if index+1 < len(expression) && expression[index+1] == '=' {
				kind, width = tokenLessEqual, 2
			} else {
				kind, width = tokenLess, 1
			}
		case '(':
			kind, width = tokenOpen, 1
		case ')':
			kind, width = tokenClose, 1
		default:
			if isWordByte(character) {
				for index < len(expression) && isWordByte(expression[index]) {
					index++
				}
				tokens = append(tokens, token{kind: tokenWord, text: expression[start:index], position: start + 1})
				if len(tokens) > 512 {
					return nil, parseError("filter contains too many tokens", start+1)
				}
				continue
			}
			return nil, parseError("unexpected character", index+1)
		}
		if width == 2 && (index+1 >= len(expression) || !validPair(character, expression[index+1])) {
			return nil, parseError("incomplete operator", index+1)
		}
		tokens = append(tokens, token{kind: kind, text: expression[index : index+width], position: index + 1})
		index += width
		if len(tokens) > 512 {
			return nil, parseError("filter contains too many tokens", start+1)
		}
	}
	return tokens, nil
}

func isWordByte(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' || character == '.' || character == '_' || character == ':' || character == '-'
}

func validPair(first, second byte) bool {
	return first == '&' && second == '&' || first == '|' && second == '|' ||
		first == '=' && second == '=' || first == '!' && second == '=' ||
		first == '>' && second == '=' || first == '<' && second == '='
}

func (p *parser) parseExpression() (*node, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (*node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept(tokenOr) {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &node{kind: nodeOr, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (*node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.accept(tokenAnd) {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &node{kind: nodeAnd, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (*node, error) {
	if p.accept(tokenNot) {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &node{kind: nodeNot, left: child}, nil
	}
	if p.accept(tokenOpen) {
		p.depth++
		if p.depth > 64 {
			return nil, parseError("filter nesting exceeds 64 levels", p.previous().position)
		}
		expression, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.accept(tokenClose) {
			return nil, p.expected("closing parenthesis")
		}
		p.depth--
		return expression, nil
	}
	return p.parsePredicate()
}

func (p *parser) parsePredicate() (*node, error) {
	field, ok := p.nextWord()
	if !ok {
		return nil, p.expected("protocol or field")
	}
	if isProtocol(field.text) {
		return &node{kind: nodeProtocol, protocol: field.text}, nil
	}
	if !isField(field.text) {
		return nil, parseError("unsupported protocol or field "+field.text, field.position)
	}
	operator, ok := p.nextComparison()
	if !ok {
		return nil, p.expected("comparison operator")
	}
	value, ok := p.nextWord()
	if !ok {
		return nil, p.expected("comparison value")
	}
	result := &node{kind: nodeComparison, field: field.text, operator: operator.kind, textValue: value.text}
	if isAddressField(field.text) {
		if operator.kind != tokenEqual && operator.kind != tokenNotEqual {
			return nil, parseError("IP address fields support only == and !=", operator.position)
		}
		result.address = net.ParseIP(value.text)
		if result.address == nil {
			return nil, parseError("invalid IP address", value.position)
		}
		if strings.HasPrefix(field.text, "ip.") {
			result.address = result.address.To4()
			if result.address == nil {
				return nil, parseError("IPv4 field requires an IPv4 address", value.position)
			}
		} else {
			if result.address.To4() != nil {
				return nil, parseError("IPv6 field requires an IPv6 address", value.position)
			}
			result.address = result.address.To16()
		}
	} else {
		maximum := uint64(^uint32(0))
		if strings.HasPrefix(field.text, "tcp.") || strings.HasPrefix(field.text, "udp.") {
			maximum = 65535
		}
		number, err := strconv.ParseUint(value.text, 10, 32)
		if err != nil || number > maximum {
			return nil, parseError("invalid numeric value for "+field.text, value.position)
		}
		result.number = uint32(number)
	}
	return result, nil
}

func (p *parser) nextWord() (token, bool) {
	if p.index >= len(p.tokens) || p.tokens[p.index].kind != tokenWord {
		return token{}, false
	}
	value := p.tokens[p.index]
	p.index++
	return value, true
}

func (p *parser) nextComparison() (token, bool) {
	if p.index >= len(p.tokens) {
		return token{}, false
	}
	value := p.tokens[p.index]
	switch value.kind {
	case tokenEqual, tokenNotEqual, tokenGreater, tokenGreaterEqual, tokenLess, tokenLessEqual:
		p.index++
		return value, true
	default:
		return token{}, false
	}
}

func (p *parser) accept(kind tokenKind) bool {
	if p.index < len(p.tokens) && p.tokens[p.index].kind == kind {
		p.index++
		return true
	}
	return false
}

func (p *parser) expected(message string) error {
	if p.index < len(p.tokens) {
		return parseError("expected "+message, p.tokens[p.index].position)
	}
	position := 1
	if len(p.tokens) > 0 {
		last := p.tokens[len(p.tokens)-1]
		position = last.position + len(last.text)
	}
	return parseError("expected "+message, position)
}

func (p *parser) previous() token {
	if p.index == 0 {
		return token{position: 1}
	}
	return p.tokens[p.index-1]
}

func parseError(message string, position int) error {
	return &ParseError{Message: message, Position: position}
}

func isProtocol(value string) bool {
	switch value {
	case "ip", "ipv6", "tcp", "udp", "dns", "icmp", "icmpv6":
		return true
	default:
		return false
	}
}

func isField(value string) bool {
	switch value {
	case "frame.len", "ip.src", "ip.dst", "ip.addr", "ipv6.src", "ipv6.dst", "ipv6.addr",
		"tcp.port", "tcp.srcport", "tcp.dstport", "udp.port", "udp.srcport", "udp.dstport":
		return true
	default:
		return false
	}
}

func isAddressField(value string) bool {
	switch value {
	case "ip.src", "ip.dst", "ip.addr", "ipv6.src", "ipv6.dst", "ipv6.addr":
		return true
	default:
		return false
	}
}

func (n *node) evaluate(info packetInfo) bool {
	switch n.kind {
	case nodeProtocol:
		return info.protocols[n.protocol]
	case nodeNot:
		return !n.left.evaluate(info)
	case nodeAnd:
		return n.left.evaluate(info) && n.right.evaluate(info)
	case nodeOr:
		return n.left.evaluate(info) || n.right.evaluate(info)
	case nodeComparison:
		return n.evaluateComparison(info)
	default:
		return false
	}
}

func (n *node) evaluateComparison(info packetInfo) bool {
	if isAddressField(n.field) {
		addresses := addressValues(info, n.field)
		if len(addresses) == 0 {
			return false
		}
		found := false
		for _, address := range addresses {
			if address.Equal(n.address) {
				found = true
				break
			}
		}
		if n.operator == tokenNotEqual {
			return !found
		}
		return found
	}
	values, ok := numericValues(info, n.field)
	if !ok {
		return false
	}
	if n.operator == tokenNotEqual {
		for _, value := range values {
			if value == n.number {
				return false
			}
		}
		return true
	}
	for _, value := range values {
		if compareNumber(value, n.number, n.operator) {
			return true
		}
	}
	return false
}

func addressValues(info packetInfo, field string) []net.IP {
	switch field {
	case "ip.src":
		return present(info.ipv4Src)
	case "ip.dst":
		return present(info.ipv4Dst)
	case "ip.addr":
		return present(info.ipv4Src, info.ipv4Dst)
	case "ipv6.src":
		return present(info.ipv6Src)
	case "ipv6.dst":
		return present(info.ipv6Dst)
	case "ipv6.addr":
		return present(info.ipv6Src, info.ipv6Dst)
	default:
		return nil
	}
}

func present(values ...net.IP) []net.IP {
	result := make([]net.IP, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, value)
		}
	}
	return result
}

func numericValues(info packetInfo, field string) ([]uint32, bool) {
	switch field {
	case "frame.len":
		return []uint32{info.length}, true
	case "tcp.port":
		if !info.protocols["tcp"] {
			return nil, false
		}
		return []uint32{info.tcpSrc, info.tcpDst}, true
	case "tcp.srcport":
		if !info.protocols["tcp"] {
			return nil, false
		}
		return []uint32{info.tcpSrc}, true
	case "tcp.dstport":
		if !info.protocols["tcp"] {
			return nil, false
		}
		return []uint32{info.tcpDst}, true
	case "udp.port":
		if !info.protocols["udp"] {
			return nil, false
		}
		return []uint32{info.udpSrc, info.udpDst}, true
	case "udp.srcport":
		if !info.protocols["udp"] {
			return nil, false
		}
		return []uint32{info.udpSrc}, true
	case "udp.dstport":
		if !info.protocols["udp"] {
			return nil, false
		}
		return []uint32{info.udpDst}, true
	default:
		return nil, false
	}
}

func compareNumber(left, right uint32, operator tokenKind) bool {
	switch operator {
	case tokenEqual:
		return left == right
	case tokenNotEqual:
		return left != right
	case tokenGreater:
		return left > right
	case tokenGreaterEqual:
		return left >= right
	case tokenLess:
		return left < right
	case tokenLessEqual:
		return left <= right
	default:
		return false
	}
}
