package netstack

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"strings"
	"time"
)

const (
	ethPIP  = 0x0800
	ethPARP = 0x0806

	ipProtoTCP  = 6
	ipProtoUDP  = 17
	ipProtoICMP = 1
)

var httpMethods = []string{
	"GET",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
	"HEAD",
	"OPTIONS",
	"CONNECT",
	"TRACE",
}

const (
	dhcpServerPort = 67
	dhcpClientPort = 68
	dhcpMagic      = 0x63825363

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5

	dhcpOptSubnetMask  = 1
	dhcpOptRouter      = 3
	dhcpOptDNS         = 6
	dhcpOptRequestedIP = 50
	dhcpOptLeaseTime   = 51
	dhcpOptMsgType     = 53
	dhcpOptServerID    = 54
	dhcpOptEnd         = 255
)

type UdpSendMessage struct {
	Key     string
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
	Payload []byte
}

type TcpConnectMessage struct {
	Key     string
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
}

type TcpSendMessage struct {
	Key  string
	Data []byte
}

type TcpCloseMessage struct {
	Key     string
	Destroy bool
}

type TcpPauseMessage struct {
	Key string
}

type TcpResumeMessage struct {
	Key string
}

type TcpFlowProtocol string

const (
	TcpFlowHTTP TcpFlowProtocol = "http"
	TcpFlowTLS  TcpFlowProtocol = "tls"
)

type TcpFlowInfo struct {
	Key       string
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Protocol  TcpFlowProtocol
	HttpMethod string
}

type NetworkCallbacks struct {
	OnUdpSend    func(message UdpSendMessage)
	OnTcpConnect func(message TcpConnectMessage)
	OnTcpSend    func(message TcpSendMessage)
	OnTcpClose   func(message TcpCloseMessage)
	OnTcpPause   func(message TcpPauseMessage)
	OnTcpResume  func(message TcpResumeMessage)
}

type NetworkStackOptions struct {
	GatewayIP      string
	VmIP           string
	GatewayMac     []byte
	VmMac          []byte
	DnsServers     []string
	Callbacks      NetworkCallbacks
	AllowTcpFlow   func(info TcpFlowInfo) bool
	TxQueueMaxBytes int
}

type TxPriority string

const (
	TxHigh TxPriority = "high"
	TxLow  TxPriority = "low"
)

type TxDropInfo struct {
	Priority     TxPriority
	Bytes        int
	Reason       string
	EvictedBytes int
}

type TcpDenyInfo struct {
	Key    string
	Reason string
}

type IcmpEvent struct {
	SrcIP     string
	DstIP     string
	ID        uint16
	Seq       uint16
	RxTime    time.Time
	ReplyTime time.Time
	Size      int
}

type tcpSession struct {
	State        string
	SrcIP        []byte
	SrcPort      uint16
	DstIP        []byte
	DstPort      uint16
	VmSeq        uint32
	VmAck        uint32
	MySeq        uint32
	MyAck        uint32
	FlowProtocol TcpFlowProtocol
	PendingData  []byte
	HTTPMethod   string
}

// NetworkStack is a small userspace ethernet/IP/TCP/UDP stack used as the QEMU net backend.
//
// It is intentionally limited and optimized for HTTP/TLS traffic mediation.
type NetworkStack struct {
	GatewayIP  string
	VmIP       string
	GatewayMac []byte
	VmMac      []byte
	DnsServers []string

	callbacks    NetworkCallbacks
	allowTcpFlow func(info TcpFlowInfo) bool

	natTable map[string]*tcpSession

	maxFlowSniff int

	rxBuffer []byte

	txQueueHigh [][]byte
	txQueueLow  [][]byte
	txQueueSize int
	txHighSize  int

	txQueueMaxBytes int

	txBufferHighWater int
	txBufferLowWater  int
	txPaused          map[string]struct{}

	// Event handlers
	onICMP        []func(IcmpEvent)
	onDHCP        []func(msgType string, ip string)
	onTcpDeny     []func(TcpDenyInfo)
	onTxDrop      []func(TxDropInfo)
	onNetActivity []func()
	onError       []func(error)
}

func NewNetworkStack(options NetworkStackOptions) *NetworkStack {
	gwIP := options.GatewayIP
	if gwIP == "" {
		gwIP = "192.168.127.1"
	}
	vmIP := options.VmIP
	if vmIP == "" {
		vmIP = "192.168.127.3"
	}
	gwMac := options.GatewayMac
	if len(gwMac) == 0 {
		gwMac = []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	}
	vmMac := options.VmMac
	if len(vmMac) == 0 {
		vmMac = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	}

	dnsServers := normalizeDnsServers(options.DnsServers)

	allow := options.AllowTcpFlow
	if allow == nil {
		allow = func(info TcpFlowInfo) bool { return true }
	}

	maxBytes := options.TxQueueMaxBytes
	if maxBytes == 0 {
		maxBytes = 4 * 1024 * 1024
	}

	s := &NetworkStack{
		GatewayIP:  gwIP,
		VmIP:       vmIP,
		GatewayMac: append([]byte(nil), gwMac...),
		VmMac:      append([]byte(nil), vmMac...),
		DnsServers: dnsServers,
		callbacks:  options.Callbacks,
		allowTcpFlow: allow,
		natTable:   map[string]*tcpSession{},
		maxFlowSniff: 8 * 1024,
		rxBuffer:   nil,
		txQueueHigh: nil,
		txQueueLow:  nil,
		txQueueSize: 0,
		txHighSize:  0,
		txQueueMaxBytes: maxBytes,
		txBufferHighWater: 16 * 1024,
		txBufferLowWater:  4 * 1024,
		txPaused: make(map[string]struct{}),
	}

	// Ensure callbacks are non-nil.
	if s.callbacks.OnUdpSend == nil {
		s.callbacks.OnUdpSend = func(UdpSendMessage) {}
	}
	if s.callbacks.OnTcpConnect == nil {
		s.callbacks.OnTcpConnect = func(TcpConnectMessage) {}
	}
	if s.callbacks.OnTcpSend == nil {
		s.callbacks.OnTcpSend = func(TcpSendMessage) {}
	}
	if s.callbacks.OnTcpClose == nil {
		s.callbacks.OnTcpClose = func(TcpCloseMessage) {}
	}
	if s.callbacks.OnTcpPause == nil {
		s.callbacks.OnTcpPause = func(TcpPauseMessage) {}
	}
	if s.callbacks.OnTcpResume == nil {
		s.callbacks.OnTcpResume = func(TcpResumeMessage) {}
	}

	return s
}

func normalizeDnsServers(servers []string) []string {
	candidates := servers
	if len(candidates) == 0 {
		return []string{"8.8.8.8"}
	}

	unique := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, server := range candidates {
		server = strings.Split(server, "%")[0]
		if net.ParseIP(server) == nil {
			continue
		}
		if strings.HasPrefix(server, "127.") {
			continue
		}
		if server == "0.0.0.0" || server == "255.255.255.255" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		// Only allow IPv4 entries.
		if net.ParseIP(server).To4() == nil {
			continue
		}
		unique = append(unique, server)
	}

	if len(unique) == 0 {
		return []string{"8.8.8.8"}
	}
	return unique
}

func (s *NetworkStack) Reset() {
	s.natTable = map[string]*tcpSession{}
	s.rxBuffer = nil
	s.txQueueHigh = nil
	s.txQueueLow = nil
	s.txQueueSize = 0
	s.txHighSize = 0
	s.txPaused = make(map[string]struct{})
}

func (s *NetworkStack) HasPendingData() bool {
	return s.txQueueSize > 0
}

func (s *NetworkStack) WriteToNetwork(data []byte) {
	s.rxBuffer = append(s.rxBuffer, data...)

	for len(s.rxBuffer) >= 4 {
		frameLen := int(binary.BigEndian.Uint32(s.rxBuffer[0:4]))
		if len(s.rxBuffer) < 4+frameLen {
			break
		}
		frame := s.rxBuffer[4 : 4+frameLen]
		s.Receive(frame)
		s.rxBuffer = s.rxBuffer[4+frameLen:]
	}
}

func (s *NetworkStack) ReadFromNetwork(maxLen int) []byte {
	if s.txQueueSize == 0 {
		return nil
	}

	remaining := maxLen
	total := 0
	chunks := make([][]byte, 0, 4)

	for remaining > 0 && s.txQueueSize > 0 {
		useHigh := len(s.txQueueHigh) > 0
		queue := &s.txQueueLow
		if useHigh {
			queue = &s.txQueueHigh
		}

		head := (*queue)[0]
		consumed := min(len(head), remaining)
		chunks = append(chunks, head[:consumed])

		if consumed == len(head) {
			*queue = (*queue)[1:]
		} else {
			(*queue)[0] = head[consumed:]
		}

		remaining -= consumed
		total += consumed
		s.txQueueSize -= consumed
		if useHigh {
			s.txHighSize -= consumed
		}
	}

	if s.txHighSize < s.txBufferLowWater && len(s.txPaused) > 0 {
		for key := range s.txPaused {
			s.callbacks.OnTcpResume(TcpResumeMessage{Key: key})
		}
		s.txPaused = make(map[string]struct{})
	}

	if len(chunks) == 1 && len(chunks[0]) == total {
		return chunks[0]
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func (s *NetworkStack) Send(payload []byte, etherType uint16) {
	if len(s.VmMac) == 0 {
		return
	}

	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], s.VmMac)
	copy(frame[6:12], s.GatewayMac)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)

	packet := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(packet[0:4], uint32(len(frame)))
	copy(packet[4:], frame)

	s.enqueueTx(packet, s.classifyTxPriority(etherType, payload))
}

func (s *NetworkStack) SendBroadcast(payload []byte, etherType uint16) {
	broadcastMac := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], broadcastMac)
	copy(frame[6:12], s.GatewayMac)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)

	packet := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(packet[0:4], uint32(len(frame)))
	copy(packet[4:], frame)

	s.enqueueTx(packet, s.classifyTxPriority(etherType, payload))
}

func (s *NetworkStack) classifyTxPriority(etherType uint16, payload []byte) TxPriority {
	if etherType == ethPARP {
		return TxHigh
	}
	if etherType != ethPIP {
		return TxLow
	}
	if len(payload) < 20 {
		return TxLow
	}
	version := payload[0] >> 4
	if version != 4 {
		return TxLow
	}
	ipProto := payload[9]
	if ipProto == ipProtoTCP {
		return TxHigh
	}
	return TxLow
}

func (s *NetworkStack) enqueueTx(packet []byte, priority TxPriority) {
	if len(packet) == 0 {
		return
	}

	if len(packet) > s.txQueueMaxBytes {
		s.emitTxDrop(TxDropInfo{Priority: priority, Bytes: len(packet), Reason: "packet-too-large"})
		return
	}

	if s.txQueueSize+len(packet) > s.txQueueMaxBytes {
		if priority == TxLow {
			s.emitTxDrop(TxDropInfo{Priority: priority, Bytes: len(packet), Reason: "queue-full"})
			return
		}

		evicted := 0
		for len(s.txQueueLow) > 0 && s.txQueueSize+len(packet) > s.txQueueMaxBytes {
			victim := s.txQueueLow[0]
			s.txQueueLow = s.txQueueLow[1:]
			evicted += len(victim)
			s.txQueueSize -= len(victim)
		}
		if evicted > 0 {
			s.emitTxDrop(TxDropInfo{Priority: TxLow, Bytes: evicted, Reason: "evicted"})
		}
		if s.txQueueSize+len(packet) > s.txQueueMaxBytes {
			s.emitTxDrop(TxDropInfo{Priority: priority, Bytes: len(packet), Reason: "queue-full", EvictedBytes: evicted})
			return
		}
	}

	if priority == TxHigh {
		s.txQueueHigh = append(s.txQueueHigh, packet)
		s.txHighSize += len(packet)
	} else {
		s.txQueueLow = append(s.txQueueLow, packet)
	}
	
	s.txQueueSize += len(packet)
	s.emitNetActivity()
}

func (s *NetworkStack) emitTxDrop(info TxDropInfo) {
	for _, fn := range s.onTxDrop {
		fn(info)
	}
}

func (s *NetworkStack) emitNetActivity() {
	for _, fn := range s.onNetActivity {
		fn()
	}
}

func (s *NetworkStack) emitError(err error) {
	for _, fn := range s.onError {
		fn(err)
	}
}

func (s *NetworkStack) emitTcpDeny(info TcpDenyInfo) {
	for _, fn := range s.onTcpDeny {
		fn(info)
	}
}

func (s *NetworkStack) emitICMP(info IcmpEvent) {
	for _, fn := range s.onICMP {
		fn(info)
	}
}

func (s *NetworkStack) emitDHCP(msgType string, ip string) {
	for _, fn := range s.onDHCP {
		fn(msgType, ip)
	}
}

// Event registration
func (s *NetworkStack) OnICMP(fn func(IcmpEvent)) { s.onICMP = append(s.onICMP, fn) }
func (s *NetworkStack) OnDHCP(fn func(msgType string, ip string)) { s.onDHCP = append(s.onDHCP, fn) }
func (s *NetworkStack) OnTcpDeny(fn func(TcpDenyInfo)) { s.onTcpDeny = append(s.onTcpDeny, fn) }
func (s *NetworkStack) OnTxDrop(fn func(TxDropInfo)) { s.onTxDrop = append(s.onTxDrop, fn) }
func (s *NetworkStack) OnNetworkActivity(fn func()) { s.onNetActivity = append(s.onNetActivity, fn) }
func (s *NetworkStack) OnError(fn func(error)) { s.onError = append(s.onError, fn) }

func (s *NetworkStack) Receive(frame []byte) {
	defer func() {
		if r := recover(); r != nil {
			s.emitError(errors.New("netstack panic"))
		}
	}()

	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]

	srcMac := frame[6:12]
	if len(s.VmMac) == 0 {
		s.VmMac = append([]byte(nil), srcMac...)
	}

	switch etherType {
	case ethPARP:
		s.handleARP(payload)
	case ethPIP:
		s.handleIP(payload)
	}
}

func (s *NetworkStack) handleARP(packet []byte) {
	if len(packet) < 28 {
		return
	}
	op := binary.BigEndian.Uint16(packet[6:8])
	if op != 1 {
		return
	}
	targetIP := packet[24:28]
	targetStr := ipToString(targetIP)
	if targetStr != s.GatewayIP {
		return
	}

	reply := make([]byte, 28)
	copy(reply[0:8], packet[0:8])
	binary.BigEndian.PutUint16(reply[6:8], 2) // reply

	copy(reply[8:14], s.GatewayMac)
	copy(reply[14:18], targetIP)
	copy(reply[18:24], packet[8:14])
	copy(reply[24:28], packet[14:18])

	s.Send(reply, ethPARP)
}

func (s *NetworkStack) handleIP(packet []byte) {
	if len(packet) < 20 {
		return
	}
	version := packet[0] >> 4
	if version != 4 {
		return
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen > len(packet) {
		totalLen = len(packet)
	}
	proto := packet[9]
	srcIP := packet[12:16]
	dstIP := packet[16:20]
	data := packet[headerLen:totalLen]

	switch proto {
	case ipProtoICMP:
		s.HandleICMP(data, srcIP, dstIP)
	case ipProtoTCP:
		s.HandleTCP(data, srcIP, dstIP)
	case ipProtoUDP:
		s.handleUDP(data, srcIP, dstIP)
	}
}

func (s *NetworkStack) CalculateChecksum(buf []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum & 0xffff)
}

func (s *NetworkStack) calculateUdpChecksum(payload, srcIP, dstIP []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = ipProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(payload)))

	ckData := append(pseudo, payload...)
	ck := s.CalculateChecksum(ckData)
	if ck == 0 {
		return 0xffff
	}
	return ck
}

func (s *NetworkStack) HandleICMP(data, srcIP, dstIP []byte) {
	if len(data) < 8 {
		return
	}
	if data[0] != 8 {
		return
	}

	wantsDebug := len(s.onICMP) > 0
	rxTime := time.Time{}
	id := uint16(0)
	seq := uint16(0)
	if wantsDebug {
		rxTime = time.Now()
		id = binary.BigEndian.Uint16(data[4:6])
		seq = binary.BigEndian.Uint16(data[6:8])
	}

	reply := make([]byte, len(data))
	copy(reply, data)
	reply[0] = 0
	reply[2] = 0
	reply[3] = 0
	ck := s.CalculateChecksum(reply)
	binary.BigEndian.PutUint16(reply[2:4], ck)

	replyTime := time.Time{}
	if wantsDebug {
		replyTime = time.Now()
		s.emitICMP(IcmpEvent{
			SrcIP:     ipToString(srcIP),
			DstIP:     ipToString(dstIP),
			ID:        id,
			Seq:       seq,
			RxTime:    rxTime,
			ReplyTime: replyTime,
			Size:      len(data),
		})
	}

	s.sendIP(reply, ipProtoICMP, dstIP, srcIP)
}

func (s *NetworkStack) sendIP(payload []byte, protocol byte, srcIP, dstIP []byte) {
	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 0)
	header[8] = 64
	header[9] = protocol
	copy(header[12:16], srcIP)
	copy(header[16:20], dstIP)
	binary.BigEndian.PutUint16(header[10:12], s.CalculateChecksum(header))

	packet := append(header, payload...)

	if len(dstIP) == 4 && dstIP[0] == 255 && dstIP[1] == 255 && dstIP[2] == 255 && dstIP[3] == 255 {
		s.SendBroadcast(packet, ethPIP)
		return
	}
	s.Send(packet, ethPIP)
}

func (s *NetworkStack) looksLikeTlsClientHello(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != 0x16 {
		return false
	}
	if data[1] != 0x03 {
		return false
	}
	return data[2] >= 0x00 && data[2] <= 0x03
}

func (s *NetworkStack) matchHTTPMethodPrefix(data []byte) (status string, method string) {
	snippetLen := min(len(data), 16)
	snippet := string(data[:snippetLen])
	for _, m := range httpMethods {
		if strings.HasPrefix(snippet, m+" ") {
			return "match", m
		}
		if strings.HasPrefix(m, snippet) {
			return "partial", ""
		}
	}
	return "none", ""
}

func (s *NetworkStack) parseHTTPRequestLine(data []byte) (method string, ok bool, isConnect bool) {
	idx := indexOfCRLF(data)
	if idx == -1 {
		return "", false, false
	}
	line := string(data[:idx])
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return "", false, false
	}
	m, target, version := parts[0], parts[1], parts[2]
	if m == "" || target == "" || version == "" {
		return "", false, false
	}
	if !strings.HasPrefix(version, "HTTP/") {
		return "", false, false
	}
	if !containsString(httpMethods, m) {
		return "", false, false
	}
	return m, true, m == "CONNECT"
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func indexOfCRLF(data []byte) int {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			return i
		}
	}
	return -1
}

type tcpFlowClass struct {
	Status    string
	Reason    string
	Method    string
	IsConnect bool
}

func (s *NetworkStack) classifyTCPFlow(data []byte) tcpFlowClass {
	if len(data) == 0 {
		return tcpFlowClass{Status: "need-more"}
	}

	if s.looksLikeTlsClientHello(data) {
		return tcpFlowClass{Status: "tls"}
	}

	status, _ := s.matchHTTPMethodPrefix(data)
	if status == "match" {
		m, ok, isConnect := s.parseHTTPRequestLine(data)
		if !ok {
			return tcpFlowClass{Status: "need-more"}
		}
		return tcpFlowClass{Status: "http", Method: m, IsConnect: isConnect}
	}
	if status == "partial" {
		return tcpFlowClass{Status: "need-more"}
	}

	if len(data) < 4 {
		return tcpFlowClass{Status: "need-more"}
	}

	return tcpFlowClass{Status: "deny", Reason: "unknown-protocol"}
}

func (s *NetworkStack) rejectTCPFlow(session *tcpSession, key string, ack uint32, reason string) {
	s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, ack, 0x14, nil)
	s.callbacks.OnTcpClose(TcpCloseMessage{Key: key, Destroy: true})
	delete(s.natTable, key)
	s.emitTcpDeny(TcpDenyInfo{Key: key, Reason: reason})
}

func (s *NetworkStack) HandleTCP(segment, srcIP, dstIP []byte) {
	if len(segment) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(segment[0:2])
	dstPort := binary.BigEndian.Uint16(segment[2:4])
	seq := binary.BigEndian.Uint32(segment[4:8])
	ack := binary.BigEndian.Uint32(segment[8:12])
	off := int(segment[12]>>4) * 4
	if off < 20 || off > len(segment) {
		return
	}
	flags := segment[13]
	payload := segment[off:]

	syn := (flags & 0x02) != 0
	fin := (flags & 0x01) != 0
	rst := (flags & 0x04) != 0

	key := tcpKey(srcIP, srcPort, dstIP, dstPort)
	session := s.natTable[key]

	if rst {
		if session != nil {
			s.callbacks.OnTcpClose(TcpCloseMessage{Key: key, Destroy: true})
			delete(s.natTable, key)
		}
		return
	}

	if syn && session == nil {
		mySeq := randomSeq()
		session = &tcpSession{
			State:        "SYN_SENT",
			SrcIP:        append([]byte(nil), srcIP...),
			SrcPort:      srcPort,
			DstIP:        append([]byte(nil), dstIP...),
			DstPort:      dstPort,
			VmSeq:        seq,
			VmAck:        ack,
			MySeq:        mySeq,
			MyAck:        seq + 1,
			FlowProtocol: "",
			PendingData:  nil,
		}
		s.natTable[key] = session

		s.callbacks.OnTcpConnect(TcpConnectMessage{Key: key, DstIP: ipToString(dstIP), DstPort: dstPort, SrcIP: ipToString(srcIP), SrcPort: srcPort})
		return
	}

	if session == nil {
		if !syn {
			ackNum := seq + uint32(max(len(payload), 1))
			s.SendTCP(srcIP, srcPort, dstIP, dstPort, 0, ackNum, 0x04, nil)
		}
		return
	}

	if len(payload) > 0 {
		var sendBuf []byte
		nextAck := session.MyAck + uint32(len(payload))

		if session.FlowProtocol == "" {
			session.PendingData = append(session.PendingData, payload...)
			class := s.classifyTCPFlow(session.PendingData)

			switch class.Status {
			case "need-more":
				if len(session.PendingData) >= s.maxFlowSniff {
					s.rejectTCPFlow(session, key, nextAck, "sniff-limit-exceeded")
					return
				}
			case "deny":
				s.rejectTCPFlow(session, key, nextAck, class.Reason)
				return
			case "http":
				if class.IsConnect {
					s.rejectTCPFlow(session, key, nextAck, "connect-not-allowed")
					return
				}
				session.FlowProtocol = TcpFlowHTTP
				session.HTTPMethod = class.Method
			case "tls":
				session.FlowProtocol = TcpFlowTLS
			}

			if session.FlowProtocol != "" {
				allowed := s.allowTcpFlow(TcpFlowInfo{Key: key, SrcIP: ipToString(session.SrcIP), SrcPort: session.SrcPort, DstIP: ipToString(session.DstIP), DstPort: session.DstPort, Protocol: session.FlowProtocol, HttpMethod: session.HTTPMethod})
				if !allowed {
					s.rejectTCPFlow(session, key, nextAck, "policy-deny")
					return
				}
				sendBuf = session.PendingData
				session.PendingData = nil
			}
		} else {
			sendBuf = payload
		}

		session.VmSeq += uint32(len(payload))
		session.MyAck = nextAck

		if len(sendBuf) > 0 {
			dataCopy := make([]byte, len(sendBuf))
			copy(dataCopy, sendBuf)
			s.callbacks.OnTcpSend(TcpSendMessage{Key: key, Data: dataCopy})
		}

		s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, 0x10, nil)
	}

	if fin {
		s.callbacks.OnTcpClose(TcpCloseMessage{Key: key, Destroy: false})
		session.MyAck++
		s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, 0x10, nil)
		if session.State == "CLOSED_BY_REMOTE" || session.State == "FIN_WAIT" {
			delete(s.natTable, key)
		} else {
			session.State = "FIN_SENT"
		}
	}
}

func randomSeq() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	// TS uses 0x0fffffff mask.
	return binary.BigEndian.Uint32(b[:]) & 0x0fffffff
}

func tcpKey(srcIP []byte, srcPort uint16, dstIP []byte, dstPort uint16) string {
	return "TCP:" + ipToString(srcIP) + ":" + itoa(int(srcPort)) + ":" + ipToString(dstIP) + ":" + itoa(int(dstPort))
}

func ipToString(ip []byte) string {
	if len(ip) != 4 {
		return ""
	}
	return itoa(int(ip[0])) + "." + itoa(int(ip[1])) + "." + itoa(int(ip[2])) + "." + itoa(int(ip[3]))
}

func itoa(n int) string {
	// small non-negative int to string
	if n == 0 {
		return "0"
	}
	buf := [16]byte{}
	pos := len(buf)
	x := n
	for x > 0 {
		pos--
		buf[pos] = byte('0' + (x % 10))
		x /= 10
	}
	return string(buf[pos:])
}

func (s *NetworkStack) SendTCP(dstIP []byte, dstPort uint16, srcIP []byte, srcPort uint16, seq uint32, ack uint32, flags byte, payload []byte) {
	if payload == nil {
		payload = nil
	}
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint32(header[4:8], seq)
	binary.BigEndian.PutUint32(header[8:12], ack)
	header[12] = 0x50
	header[13] = flags
	binary.BigEndian.PutUint16(header[14:16], 65535)
	binary.BigEndian.PutUint16(header[16:18], 0)
	binary.BigEndian.PutUint16(header[18:20], 0)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))

	ckData := make([]byte, 0, len(pseudo)+len(header)+len(payload))
	ckData = append(ckData, pseudo...)
	ckData = append(ckData, header...)
	ckData = append(ckData, payload...)
	ck := s.CalculateChecksum(ckData)
	binary.BigEndian.PutUint16(header[16:18], ck)

	segment := append(header, payload...)
	s.sendIP(segment, ipProtoTCP, srcIP, dstIP)
}

func (s *NetworkStack) handleUDP(segment, srcIP, dstIP []byte) {
	if len(segment) < 8 {
		return
	}
	srcPort := binary.BigEndian.Uint16(segment[0:2])
	dstPort := binary.BigEndian.Uint16(segment[2:4])
	payload := segment[8:]

	if srcPort == dhcpClientPort && dstPort == dhcpServerPort {
		s.handleDHCP(payload)
		return
	}

	key := "UDP:" + ipToString(srcIP) + ":" + itoa(int(srcPort)) + ":" + ipToString(dstIP) + ":" + itoa(int(dstPort))
	s.callbacks.OnUdpSend(UdpSendMessage{Key: key, DstIP: ipToString(dstIP), DstPort: dstPort, SrcIP: ipToString(srcIP), SrcPort: srcPort, Payload: append([]byte(nil), payload...)})
}

func (s *NetworkStack) handleDHCP(data []byte) {
	if len(data) < 240 {
		return
	}
	op := data[0]
	if op != 1 {
		return
	}
	xid := binary.BigEndian.Uint32(data[4:8])
	flags := binary.BigEndian.Uint16(data[10:12])
	chaddr := data[28 : 28+16]

	magic := binary.BigEndian.Uint32(data[236:240])
	if magic != dhcpMagic {
		return
	}

	msgType := byte(0)
	i := 240
	for i < len(data) {
		opt := data[i]
		if opt == dhcpOptEnd {
			break
		}
		if opt == 0 {
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		ln := int(data[i+1])
		if i+2+ln > len(data) {
			break
		}
		optData := data[i+2 : i+2+ln]

		if opt == dhcpOptMsgType && ln >= 1 {
			msgType = optData[0]
		} else if opt == dhcpOptRequestedIP {
			// ignored
		}
		i += 2 + ln
	}

	switch msgType {
	case dhcpDiscover:
		s.sendDHCPReply(dhcpOffer, xid, chaddr, flags)
	case dhcpRequest:
		s.sendDHCPReply(dhcpAck, xid, chaddr, flags)
	}
}

func (s *NetworkStack) sendDHCPReply(msgType byte, xid uint32, chaddr []byte, flags uint16) {
	reply := make([]byte, 300)
	reply[0] = 2 // BOOTREPLY
	reply[1] = 1
	reply[2] = 6
	reply[3] = 0
	binary.BigEndian.PutUint32(reply[4:8], xid)
	binary.BigEndian.PutUint16(reply[8:10], 0)
	binary.BigEndian.PutUint16(reply[10:12], flags)

	vmParts := parseIPv4String(s.VmIP)
	gwParts := parseIPv4String(s.GatewayIP)
	if vmParts == nil || gwParts == nil {
		return
	}

	copy(reply[16:20], vmParts)
	copy(reply[20:24], gwParts)
	copy(reply[28:44], chaddr)
	binary.BigEndian.PutUint32(reply[236:240], dhcpMagic)

	off := 240
	// msg-type
	reply[off] = dhcpOptMsgType
	reply[off+1] = 1
	reply[off+2] = msgType
	off += 3

	// server-id
	reply[off] = dhcpOptServerID
	reply[off+1] = 4
	copy(reply[off+2:off+6], gwParts)
	off += 6

	// lease time
	reply[off] = dhcpOptLeaseTime
	reply[off+1] = 4
	binary.BigEndian.PutUint32(reply[off+2:off+6], 86400)
	off += 6

	// subnet mask /24
	reply[off] = dhcpOptSubnetMask
	reply[off+1] = 4
	reply[off+2] = 255
	reply[off+3] = 255
	reply[off+4] = 255
	reply[off+5] = 0
	off += 6

	// router
	reply[off] = dhcpOptRouter
	reply[off+1] = 4
	copy(reply[off+2:off+6], gwParts)
	off += 6

	// dns
	dnsServers := s.DnsServers
	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8"}
	}
	dnsEntries := make([][]byte, 0, len(dnsServers))
	for _, server := range dnsServers {
		parts := parseIPv4String(server)
		if parts == nil {
			continue
		}
		dnsEntries = append(dnsEntries, parts)
	}
	if len(dnsEntries) == 0 {
		dnsEntries = append(dnsEntries, []byte{8, 8, 8, 8})
	}
	reply[off] = dhcpOptDNS
	reply[off+1] = byte(len(dnsEntries) * 4)
	off += 2
	for _, p := range dnsEntries {
		copy(reply[off:off+4], p)
		off += 4
	}

	// broadcast
	reply[off] = 28
	reply[off+1] = 4
	copy(reply[off+2:off+5], vmParts[0:3])
	reply[off+5] = 255
	off += 6

	reply[off] = dhcpOptEnd

	dhcpLen := 300

	udpLen := 8 + dhcpLen
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], dhcpServerPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dhcpClientPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	udpPayload := append(udpHeader, reply...)

	srcIP := gwParts
	dstIP := []byte{255, 255, 255, 255}

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+len(udpPayload)))
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)
	ipHeader[8] = 64
	ipHeader[9] = ipProtoUDP
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)
	binary.BigEndian.PutUint16(ipHeader[10:12], s.CalculateChecksum(ipHeader))

	ipPacket := append(ipHeader, udpPayload...)

	var dstMac []byte
	if (flags & 0x8000) != 0 {
		dstMac = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else {
		dstMac = chaddr[0:6]
	}

	frame := make([]byte, 14+len(ipPacket))
	copy(frame[0:6], dstMac)
	copy(frame[6:12], s.GatewayMac)
	binary.BigEndian.PutUint16(frame[12:14], ethPIP)
	copy(frame[14:], ipPacket)

	packet := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(packet[0:4], uint32(len(frame)))
	copy(packet[4:], frame)

	// DHCP is required for connectivity; high priority.
	s.enqueueTx(packet, TxHigh)

	label := "ACK"
	if msgType == dhcpOffer {
		label = "OFFER"
	}
	s.emitDHCP(label, s.VmIP)
}

func parseIPv4String(ip string) []byte {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v := 0
		for _, ch := range parts[i] {
			if ch < '0' || ch > '9' {
				return nil
			}
			v = v*10 + int(ch-'0')
			if v > 255 {
				return nil
			}
		}
		out[i] = byte(v)
	}
	return out
}

func (s *NetworkStack) HandleUdpResponse(msg struct {
	Data    []byte
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}) {
	data := msg.Data
	srcIP := msg.SrcIP
	srcPort := msg.SrcPort
	dstIP := msg.DstIP
	dstPort := msg.DstPort

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], dstPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], srcPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(data)))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	dstIPBuf := parseIPv4String(dstIP)
	srcIPBuf := parseIPv4String(srcIP)
	if dstIPBuf == nil || srcIPBuf == nil {
		return
	}

	payload := make([]byte, 0, 8+len(data))
	payload = append(payload, udpHeader...)
	payload = append(payload, data...)
	ck := s.calculateUdpChecksum(payload, dstIPBuf, srcIPBuf)
	binary.BigEndian.PutUint16(udpHeader[6:8], ck)

	withChecksum := make([]byte, 0, 8+len(data))
	withChecksum = append(withChecksum, udpHeader...)
	withChecksum = append(withChecksum, data...)

	s.sendIP(withChecksum, ipProtoUDP, dstIPBuf, srcIPBuf)
}

func (s *NetworkStack) HandleTcpConnected(key string) {
	session := s.natTable[key]
	if session == nil {
		return
	}
	session.State = "ESTABLISHED"
	s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, 0x12, nil)
	session.MySeq++
}

func (s *NetworkStack) HandleTcpData(key string, data []byte) {
	session := s.natTable[key]
	if session == nil {
		return
	}

	payload := make([]byte, len(data))
	copy(payload, data)
	const mss = 1460
	off := 0
	for off < len(payload) {
		chunkSize := min(mss, len(payload)-off)
		chunk := payload[off : off+chunkSize]
		isLast := off+chunkSize >= len(payload)
		flags := byte(0x10)
		if isLast {
			flags = 0x18
		}
		s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, flags, chunk)
		session.MySeq += uint32(len(chunk))
		off += chunkSize
	}

	if s.txHighSize > s.txBufferHighWater {
		if _, ok := s.txPaused[key]; !ok {
			s.txPaused[key] = struct{}{}
			s.callbacks.OnTcpPause(TcpPauseMessage{Key: key})
		}
	}
}

func (s *NetworkStack) HandleTcpEnd(key string) {
	session := s.natTable[key]
	if session == nil {
		return
	}
	s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, 0x11, nil)
	session.MySeq++
	session.State = "FIN_WAIT"
}

func (s *NetworkStack) HandleTcpError(key string) {
	session := s.natTable[key]
	if session == nil {
		return
	}
	s.SendTCP(session.SrcIP, session.SrcPort, session.DstIP, session.DstPort, session.MySeq, session.MyAck, 0x04, nil)
	delete(s.natTable, key)
}

func (s *NetworkStack) HandleTcpClosed(key string) {
	session := s.natTable[key]
	if session != nil {
		session.State = "CLOSED_BY_REMOTE"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var errTooSmall = errors.New("too small")

// Ensure unused imports don't get stripped in future edits.
var _ = math.MaxFloat64
var _ = errTooSmall
