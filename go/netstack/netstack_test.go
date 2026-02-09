package netstack

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func checksum16(buf []byte) uint16 {
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

func buildEthernetFrame(dstMac, srcMac []byte, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMac)
	copy(frame[6:12], srcMac)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4Packet(srcIP, dstIP []byte, protocol byte, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(hdr[4:6], 0)
	binary.BigEndian.PutUint16(hdr[6:8], 0)
	hdr[8] = 64
	hdr[9] = protocol
	copy(hdr[12:16], srcIP)
	copy(hdr[16:20], dstIP)
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	binary.BigEndian.PutUint16(hdr[10:12], checksum16(hdr))
	return append(hdr, payload...)
}

func buildUdpDatagram(srcPort, dstPort uint16, payload []byte, checksum *uint16) []byte {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(8+len(payload)))
	if checksum != nil {
		binary.BigEndian.PutUint16(hdr[6:8], *checksum)
	} else {
		binary.BigEndian.PutUint16(hdr[6:8], 0)
	}
	return append(hdr, payload...)
}

func buildTcpSegment(srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	if payload == nil {
		payload = []byte{}
	}
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], ack)
	hdr[12] = 0x50
	hdr[13] = flags
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	binary.BigEndian.PutUint16(hdr[16:18], 0)
	binary.BigEndian.PutUint16(hdr[18:20], 0)
	return append(hdr, payload...)
}

func buildIcmpEchoRequest(id, seq uint16, payload []byte) []byte {
	if payload == nil {
		payload = []byte("hello")
	}
	msg := make([]byte, 8+len(payload))
	msg[0] = 8
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	binary.BigEndian.PutUint16(msg[2:4], checksum16(msg))
	return msg
}

func qemuPacketFromFrame(frame []byte) []byte {
	pkt := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(len(frame)))
	copy(pkt[4:], frame)
	return pkt
}

func decodeFramesFromQemuData(data []byte) ([][]byte, error) {
	frames := make([][]byte, 0, 8)
	off := 0
	for off+4 <= len(data) {
		ln := int(binary.BigEndian.Uint32(data[off : off+4]))
		if off+4+ln > len(data) {
			return nil, errIncomplete
		}
		frames = append(frames, data[off+4:off+4+ln])
		off += 4 + ln
	}
	if off != len(data) {
		return nil, errTrailing
	}
	return frames, nil
}

var (
	errIncomplete = &testErr{"incomplete qemu frame"}
	errTrailing   = &testErr{"trailing bytes"}
)

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

func drainAllQemuTx(t *testing.T, stack *NetworkStack) []byte {
	t.Helper()
	chunks := make([][]byte, 0, 8)
	iterations := 0
	for stack.HasPendingData() {
		iterations++
		if iterations > 10000 {
			t.Fatalf("drainAllQemuTx: exceeded iterations")
		}
		chunk := stack.ReadFromNetwork(1 << 20)
		if chunk == nil || len(chunk) == 0 {
			t.Fatalf("drainAllQemuTx: got empty chunk")
		}
		chunks = append(chunks, append([]byte(nil), chunk...))
	}
	return bytes.Join(chunks, nil)
}

type parsedEthernet struct {
	dstMac    []byte
	srcMac    []byte
	etherType uint16
	payload   []byte
}

func parseEthernet(frame []byte) parsedEthernet {
	return parsedEthernet{
		dstMac:    frame[0:6],
		srcMac:    frame[6:12],
		etherType: binary.BigEndian.Uint16(frame[12:14]),
		payload:   frame[14:],
	}
}

type parsedIPv4 struct {
	version  byte
	ihl      int
	totalLen int
	protocol byte
	srcIP    []byte
	dstIP    []byte
	header   []byte
	payload  []byte
}

func parseIPv4(packet []byte) parsedIPv4 {
	version := packet[0] >> 4
	ihl := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen > len(packet) {
		totalLen = len(packet)
	}
	return parsedIPv4{
		version:  version,
		ihl:      ihl,
		totalLen: totalLen,
		protocol: packet[9],
		srcIP:    packet[12:16],
		dstIP:    packet[16:20],
		header:   packet[0:ihl],
		payload:  packet[ihl:totalLen],
	}
}

func TestCalculateChecksumMatchesIndependentImplementation(t *testing.T) {
	stack := NewNetworkStack(NetworkStackOptions{Callbacks: NetworkCallbacks{}})
	even := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	odd := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}

	if stack.CalculateChecksum(even) != checksum16(even) {
		t.Fatalf("checksum mismatch")
	}
	if stack.CalculateChecksum(odd) != checksum16(odd) {
		t.Fatalf("checksum mismatch")
	}
}

func TestArpRequestForGatewayGetsReply(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayIP:  "192.168.127.1",
		VmIP:       "192.168.127.3",
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks:  NetworkCallbacks{},
	})

	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], vmMac)
	copy(arp[14:18], []byte{192, 168, 127, 3})
	copy(arp[18:24], []byte{0, 0, 0, 0, 0, 0})
	copy(arp[24:28], []byte{192, 168, 127, 1})

	frame := buildEthernetFrame([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, vmMac, ethPARP, arp)
	stack.Receive(frame)

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}

	out := parseEthernet(frames[0])
	if out.etherType != ethPARP {
		t.Fatalf("expected ARP")
	}
	if !bytes.Equal(out.dstMac, vmMac) {
		t.Fatalf("dst mac mismatch")
	}
	if !bytes.Equal(out.srcMac, gatewayMac) {
		t.Fatalf("src mac mismatch")
	}

	reply := out.payload
	if binary.BigEndian.Uint16(reply[6:8]) != 2 {
		t.Fatalf("expected arp reply")
	}
	if !bytes.Equal(reply[8:14], gatewayMac) {
		t.Fatalf("sender mac mismatch")
	}
	if !bytes.Equal(reply[14:18], []byte{192, 168, 127, 1}) {
		t.Fatalf("sender ip mismatch")
	}
}

func TestIcmpEchoRequestProducesEchoReply(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks:  NetworkCallbacks{},
	})

	icmpEvents := 0
	stack.OnICMP(func(_ IcmpEvent) { icmpEvents++ })

	icmpReq := buildIcmpEchoRequest(0x1234, 9, []byte("abc"))
	ipPacket := buildIPv4Packet([]byte{192, 168, 127, 3}, []byte{8, 8, 8, 8}, ipProtoICMP, icmpReq)
	frame := buildEthernetFrame(gatewayMac, vmMac, ethPIP, ipPacket)
	stack.Receive(frame)

	if icmpEvents != 1 {
		t.Fatalf("expected icmp event")
	}

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame")
	}

	eth := parseEthernet(frames[0])
	if eth.etherType != ethPIP {
		t.Fatalf("expected IPv4")
	}

	ipOut := parseIPv4(eth.payload)
	if ipOut.protocol != ipProtoICMP {
		t.Fatalf("expected icmp")
	}
	if !bytes.Equal(ipOut.srcIP, []byte{8, 8, 8, 8}) {
		t.Fatalf("src ip mismatch")
	}
	if !bytes.Equal(ipOut.dstIP, []byte{192, 168, 127, 3}) {
		t.Fatalf("dst ip mismatch")
	}

	icmpReply := ipOut.payload
	if icmpReply[0] != 0 {
		t.Fatalf("expected echo reply")
	}
	if binary.BigEndian.Uint16(icmpReply[4:6]) != 0x1234 {
		t.Fatalf("id mismatch")
	}
	if binary.BigEndian.Uint16(icmpReply[6:8]) != 9 {
		t.Fatalf("seq mismatch")
	}

	tmp := append([]byte(nil), icmpReply...)
	binary.BigEndian.PutUint16(tmp[2:4], 0)
	if binary.BigEndian.Uint16(icmpReply[2:4]) != checksum16(tmp) {
		t.Fatalf("icmp checksum mismatch")
	}
}

func TestWriteToNetworkParsesQemuFramingPartialWrites(t *testing.T) {
	events := make([]UdpSendMessage, 0, 1)
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks: NetworkCallbacks{
			OnUdpSend: func(m UdpSendMessage) { events = append(events, m) },
		},
	})

	udp := buildUdpDatagram(1234, 53, []byte{1, 2, 3}, nil)
	ipPacket := buildIPv4Packet([]byte{192, 168, 127, 3}, []byte{8, 8, 8, 8}, ipProtoUDP, udp)
	frame := buildEthernetFrame(gatewayMac, vmMac, ethPIP, ipPacket)
	qemuPkt := qemuPacketFromFrame(frame)

	stack.WriteToNetwork(qemuPkt[:7])
	if len(events) != 0 {
		t.Fatalf("expected no events")
	}
	stack.WriteToNetwork(qemuPkt[7:])

	if len(events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if events[0].DstPort != 53 {
		t.Fatalf("dst port mismatch")
	}
	if !bytes.Equal(events[0].Payload, []byte{1, 2, 3}) {
		t.Fatalf("payload mismatch")
	}
}

func TestDhcpDoesNotAdvertiseLoopbackDnsServers(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	stack := NewNetworkStack(NetworkStackOptions{
		GatewayIP:  "192.168.127.1",
		VmIP:       "192.168.127.3",
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"127.0.0.53"},
		Callbacks:  NetworkCallbacks{},
	})

	xid := uint32(0x0a0b0c0d)
	bootp := make([]byte, 240)
	bootp[0] = 1
	bootp[1] = 1
	bootp[2] = 6
	bootp[3] = 0
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	binary.BigEndian.PutUint16(bootp[8:10], 0)
	binary.BigEndian.PutUint16(bootp[10:12], 0x8000)
	copy(bootp[28:34], vmMac)
	binary.BigEndian.PutUint32(bootp[236:240], dhcpMagic)

	discoverOpts := []byte{dhcpOptMsgType, 1, dhcpDiscover, dhcpOptEnd}
	dhcp := append(bootp, discoverOpts...)

	udp := buildUdpDatagram(dhcpClientPort, dhcpServerPort, dhcp, nil)
	ipPacket := buildIPv4Packet([]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255}, ipProtoUDP, udp)
	frame := buildEthernetFrame([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, vmMac, ethPIP, ipPacket)

	stack.Receive(frame)

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame")
	}
	eth := parseEthernet(frames[0])
	ipOut := parseIPv4(eth.payload)
	udpOut := ipOut.payload
	dhcpOut := udpOut[8:]

	opts := dhcpOut[240:]
	off := 0
	var dns []byte
	for off < len(opts) {
		code := opts[off]
		off++
		if code == dhcpOptEnd {
			break
		}
		if code == 0 {
			continue
		}
		ln := int(opts[off])
		off++
		val := opts[off : off+ln]
		off += ln
		if code == dhcpOptDNS {
			dns = val
			break
		}
	}
	if dns == nil {
		t.Fatalf("expected dns option")
	}
	if len(dns) != 4 {
		t.Fatalf("expected one dns entry")
	}
	if !bytes.Equal(dns, []byte{8, 8, 8, 8}) {
		t.Fatalf("expected 8.8.8.8, got %v", dns)
	}
}

func TestDhcpDiscoverOfferThenRequestAck(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	stack := NewNetworkStack(NetworkStackOptions{
		GatewayIP:  "192.168.127.1",
		VmIP:       "192.168.127.3",
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"1.1.1.1"},
		Callbacks:  NetworkCallbacks{},
	})

	dhcpEvents := make([]string, 0, 2)
	stack.OnDHCP(func(mt, _ string) {
		dhcpEvents = append(dhcpEvents, mt)
	})

	buildDhcpMessage := func(msgType byte, xid uint32, flags uint16) []byte {
		bootp := make([]byte, 240)
		bootp[0] = 1
		bootp[1] = 1
		bootp[2] = 6
		bootp[3] = 0
		binary.BigEndian.PutUint32(bootp[4:8], xid)
		binary.BigEndian.PutUint16(bootp[10:12], flags)
		copy(bootp[28:34], vmMac)
		binary.BigEndian.PutUint32(bootp[236:240], dhcpMagic)
		opts := []byte{dhcpOptMsgType, 1, msgType, dhcpOptEnd}
		return append(bootp, opts...)
	}

	xid := uint32(0x0a0b0c0d)
	for _, mt := range []byte{dhcpDiscover, dhcpRequest} {
		dhcp := buildDhcpMessage(mt, xid, 0x8000)
		udp := buildUdpDatagram(dhcpClientPort, dhcpServerPort, dhcp, nil)
		ipPacket := buildIPv4Packet([]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255}, ipProtoUDP, udp)
		frame := buildEthernetFrame([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, vmMac, ethPIP, ipPacket)
		stack.Receive(frame)
	}

	if len(dhcpEvents) != 2 || dhcpEvents[0] != "OFFER" || dhcpEvents[1] != "ACK" {
		t.Fatalf("unexpected events: %v", dhcpEvents)
	}

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames")
	}

	expectedTypes := []byte{dhcpOffer, dhcpAck}
	for idx, expected := range expectedTypes {
		eth := parseEthernet(frames[idx])
		ipOut := parseIPv4(eth.payload)
		if ipOut.protocol != ipProtoUDP {
			t.Fatalf("expected udp")
		}
		if !bytes.Equal(ipOut.dstIP, []byte{255, 255, 255, 255}) {
			t.Fatalf("expected broadcast")
		}
		udpOut := ipOut.payload
		if binary.BigEndian.Uint16(udpOut[0:2]) != dhcpServerPort {
			t.Fatalf("src port mismatch")
		}
		if binary.BigEndian.Uint16(udpOut[2:4]) != dhcpClientPort {
			t.Fatalf("dst port mismatch")
		}
		dhcpOut := udpOut[8:]
		if dhcpOut[0] != 2 {
			t.Fatalf("expected BOOTREPLY")
		}
		if binary.BigEndian.Uint32(dhcpOut[4:8]) != xid {
			t.Fatalf("xid mismatch")
		}
		if binary.BigEndian.Uint32(dhcpOut[236:240]) != dhcpMagic {
			t.Fatalf("magic mismatch")
		}
		if dhcpOut[240] != dhcpOptMsgType || dhcpOut[241] != 1 {
			t.Fatalf("expected msg-type option")
		}
		mt := dhcpOut[242]
		if mt != expected {
			t.Fatalf("expected %d, got %d", expected, mt)
		}
	}
}

func TestTcpSynCreatesSessionAndHandleTcpConnectedEmitsSynAck(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	connects := make([]TcpConnectMessage, 0, 1)
	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { connects = append(connects, m) },
		},
	})

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}

	stack.HandleTCP(buildTcpSegment(40000, 80, 1000, 0, 0x02, nil), srcIP, dstIP)
	if len(connects) != 1 {
		t.Fatalf("expected connect")
	}
	key := connects[0].Key
	stack.HandleTcpConnected(key)

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame")
	}

	eth := parseEthernet(frames[0])
	ipOut := parseIPv4(eth.payload)
	if ipOut.protocol != ipProtoTCP {
		t.Fatalf("expected tcp")
	}

	tcp := ipOut.payload
	flags := tcp[13]
	if flags&0x12 != 0x12 {
		t.Fatalf("expected SYN+ACK")
	}
	if binary.BigEndian.Uint16(tcp[0:2]) != 80 {
		t.Fatalf("src port mismatch")
	}
	if binary.BigEndian.Uint16(tcp[2:4]) != 40000 {
		t.Fatalf("dst port mismatch")
	}

	tcpLen := ipOut.totalLen - ipOut.ihl
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], ipOut.srcIP)
	copy(pseudo[4:8], ipOut.dstIP)
	pseudo[8] = 0
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	tcpCopy := append([]byte(nil), tcp[:tcpLen]...)
	got := binary.BigEndian.Uint16(tcpCopy[16:18])
	binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
	if got != checksum16(append(pseudo, tcpCopy...)) {
		t.Fatalf("tcp checksum mismatch")
	}
}

func TestTcpFlowClassificationHttpEmitsOnTcpSendAndPassesAllowInfo(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	var lastKey string
	sends := make([]TcpSendMessage, 0, 1)
	allowCalls := make([]TcpFlowInfo, 0, 1)

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		AllowTcpFlow: func(info TcpFlowInfo) bool {
			allowCalls = append(allowCalls, info)
			return true
		},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { lastKey = m.Key },
			OnTcpSend:    func(m TcpSendMessage) { sends = append(sends, m) },
		},
	})

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}

	stack.HandleTCP(buildTcpSegment(40001, 80, 1, 0, 0x02, nil), srcIP, dstIP)
	if lastKey == "" {
		t.Fatalf("expected key")
	}
	stack.HandleTcpConnected(lastKey)
	_ = drainAllQemuTx(t, stack)

	http := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	stack.HandleTCP(buildTcpSegment(40001, 80, 2, 0, 0x18, http), srcIP, dstIP)

	if len(allowCalls) != 1 {
		t.Fatalf("expected allow call")
	}
	if allowCalls[0].Protocol != TcpFlowHTTP {
		t.Fatalf("expected http protocol")
	}
	if allowCalls[0].HttpMethod != "GET" {
		t.Fatalf("expected method GET")
	}

	if len(sends) != 1 {
		t.Fatalf("expected send")
	}
	if !bytes.Equal(sends[0].Data, http) {
		t.Fatalf("data mismatch")
	}

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame")
	}
	ipOut := parseIPv4(parseEthernet(frames[0]).payload)
	tcpOut := ipOut.payload
	if tcpOut[13]&0x10 != 0x10 {
		t.Fatalf("expected ack")
	}
}

func TestTcpFlowRejectsConnectAndUnknownProtocols(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	closes := make([]TcpCloseMessage, 0, 2)
	denies := make([]TcpDenyInfo, 0, 2)
	var key string

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { key = m.Key },
			OnTcpClose:   func(m TcpCloseMessage) { closes = append(closes, m) },
		},
	})
	stack.OnTcpDeny(func(info TcpDenyInfo) { denies = append(denies, info) })

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}

	stack.HandleTCP(buildTcpSegment(40002, 80, 1, 0, 0x02, nil), srcIP, dstIP)
	stack.HandleTcpConnected(key)
	_ = drainAllQemuTx(t, stack)

	connectReq := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	stack.HandleTCP(buildTcpSegment(40002, 80, 2, 0, 0x18, connectReq), srcIP, dstIP)

	if len(closes) != 1 || !closes[0].Destroy {
		t.Fatalf("expected close destroy")
	}
	if len(denies) != 1 || denies[0].Reason != "connect-not-allowed" {
		t.Fatalf("expected connect-not-allowed")
	}

	tx1 := drainAllQemuTx(t, stack)
	frames1, _ := decodeFramesFromQemuData(tx1)
	if len(frames1) != 1 {
		t.Fatalf("expected 1 frame")
	}
	tcp1 := parseIPv4(parseEthernet(frames1[0]).payload).payload
	if tcp1[13]&0x04 != 0x04 {
		t.Fatalf("expected RST")
	}

	// unknown protocol
	key = ""
	closes = closes[:0]
	denies = denies[:0]

	stack.HandleTCP(buildTcpSegment(40003, 80, 1, 0, 0x02, nil), srcIP, dstIP)
	key2 := key
	if key2 == "" {
		t.Fatalf("expected key")
	}
	stack.HandleTcpConnected(key2)
	_ = drainAllQemuTx(t, stack)

	ssh := []byte("SSH-2.0-OpenSSH_9.0\r\n")
	stack.HandleTCP(buildTcpSegment(40003, 80, 2, 0, 0x18, ssh), srcIP, dstIP)

	if len(closes) != 1 {
		t.Fatalf("expected close")
	}
	if len(denies) != 1 || denies[0].Reason != "unknown-protocol" {
		t.Fatalf("expected unknown-protocol")
	}
}

func TestTcpSniffLimitExceededRejectsIncompleteHttpRequestLine(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	closes := make([]TcpCloseMessage, 0, 1)
	denies := make([]TcpDenyInfo, 0, 1)
	var key string

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { key = m.Key },
			OnTcpClose:   func(m TcpCloseMessage) { closes = append(closes, m) },
		},
	})
	stack.OnTcpDeny(func(info TcpDenyInfo) { denies = append(denies, info) })

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}

	stack.HandleTCP(buildTcpSegment(40004, 80, 1, 0, 0x02, nil), srcIP, dstIP)
	stack.HandleTcpConnected(key)
	_ = drainAllQemuTx(t, stack)

	payload := []byte("GET /" + string(bytes.Repeat([]byte("a"), 8192)))
	stack.HandleTCP(buildTcpSegment(40004, 80, 2, 0, 0x18, payload), srcIP, dstIP)

	if len(closes) != 1 {
		t.Fatalf("expected close")
	}
	if len(denies) != 1 || denies[0].Reason != "sniff-limit-exceeded" {
		t.Fatalf("expected sniff-limit-exceeded")
	}
}

func TestAllowTcpFlowCanDenyTlsFlows(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	closes := make([]TcpCloseMessage, 0, 1)
	denies := make([]TcpDenyInfo, 0, 1)
	var key string

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		AllowTcpFlow: func(info TcpFlowInfo) bool {
			return info.Protocol != TcpFlowTLS
		},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { key = m.Key },
			OnTcpClose:   func(m TcpCloseMessage) { closes = append(closes, m) },
		},
	})
	stack.OnTcpDeny(func(info TcpDenyInfo) { denies = append(denies, info) })

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}

	stack.HandleTCP(buildTcpSegment(40005, 443, 1, 0, 0x02, nil), srcIP, dstIP)
	stack.HandleTcpConnected(key)
	_ = drainAllQemuTx(t, stack)

	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b}
	stack.HandleTCP(buildTcpSegment(40005, 443, 2, 0, 0x18, tlsHello), srcIP, dstIP)

	if len(closes) != 1 {
		t.Fatalf("expected close")
	}
	if len(denies) != 1 || denies[0].Reason != "policy-deny" {
		t.Fatalf("expected policy-deny")
	}
}

func TestTcpFlowControlPausesAndResumes(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	pauses := make([]TcpPauseMessage, 0, 1)
	resumes := make([]TcpResumeMessage, 0, 1)
	var key string

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks: NetworkCallbacks{
			OnTcpConnect: func(m TcpConnectMessage) { key = m.Key },
			OnTcpPause:   func(m TcpPauseMessage) { pauses = append(pauses, m) },
			OnTcpResume:  func(m TcpResumeMessage) { resumes = append(resumes, m) },
		},
	})

	srcIP := []byte{192, 168, 127, 3}
	dstIP := []byte{93, 184, 216, 34}
	stack.HandleTCP(buildTcpSegment(40006, 80, 1, 0, 0x02, nil), srcIP, dstIP)
	stack.HandleTcpConnected(key)
	_ = drainAllQemuTx(t, stack)

	stack.HandleTcpData(key, bytes.Repeat([]byte{0x61}, 20000))
	if len(pauses) != 1 || pauses[0].Key != key {
		t.Fatalf("expected pause")
	}

	_ = drainAllQemuTx(t, stack)
	if len(resumes) != 1 || resumes[0].Key != key {
		t.Fatalf("expected resume")
	}
}

func TestHandleUdpResponseSetsUdpChecksumCorrectly(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	stack := NewNetworkStack(NetworkStackOptions{
		GatewayMac: gatewayMac,
		VmMac:      vmMac,
		DnsServers: []string{"8.8.8.8"},
		Callbacks:  NetworkCallbacks{},
	})

	data := []byte{0xde, 0xad, 0xbe, 0xef}
	stack.HandleUdpResponse(struct {
		Data    []byte
		SrcIP   string
		SrcPort uint16
		DstIP   string
		DstPort uint16
	}{
		Data:    data,
		SrcIP:   "8.8.8.8",
		SrcPort: 53,
		DstIP:   "192.168.127.3",
		DstPort: 33333,
	})

	tx := drainAllQemuTx(t, stack)
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame")
	}

	eth := parseEthernet(frames[0])
	ipOut := parseIPv4(eth.payload)
	if ipOut.protocol != ipProtoUDP {
		t.Fatalf("expected udp")
	}

	udp := ipOut.payload
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	udpCopy := append([]byte(nil), udp[:udpLen]...)
	got := binary.BigEndian.Uint16(udpCopy[6:8])
	binary.BigEndian.PutUint16(udpCopy[6:8], 0)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], ipOut.srcIP)
	copy(pseudo[4:8], ipOut.dstIP)
	pseudo[8] = 0
	pseudo[9] = ipProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))

	expected := checksum16(append(pseudo, udpCopy...))
	if expected == 0 {
		expected = 0xffff
	}
	if got != expected {
		t.Fatalf("udp checksum mismatch")
	}
}

func TestCapsQemuTxBufferingAndDropsLowPriorityFrames(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	txQueueMaxBytes := 1024
	stack := NewNetworkStack(NetworkStackOptions{
		GatewayIP:      "192.168.127.1",
		VmIP:           "192.168.127.3",
		GatewayMac:     gatewayMac,
		VmMac:          vmMac,
		DnsServers:     []string{"8.8.8.8"},
		TxQueueMaxBytes: txQueueMaxBytes,
		Callbacks:      NetworkCallbacks{},
	})

	drops := 0
	stack.OnTxDrop(func(_ TxDropInfo) { drops++ })

	for i := 0; i < 200; i++ {
		req := buildIcmpEchoRequest(42, uint16(i), bytes.Repeat([]byte{0xaa}, 32))
		packet := buildIPv4Packet([]byte{192, 168, 127, 3}, []byte{192, 168, 127, 1}, ipProtoICMP, req)
		frame := buildEthernetFrame(gatewayMac, vmMac, ethPIP, packet)
		stack.WriteToNetwork(qemuPacketFromFrame(frame))
	}

	tx := drainAllQemuTx(t, stack)
	if len(tx) > txQueueMaxBytes {
		t.Fatalf("tx length %d exceeds cap %d", len(tx), txQueueMaxBytes)
	}
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(frames) >= 200 {
		t.Fatalf("expected some drops")
	}
	if drops == 0 {
		t.Fatalf("expected tx-drop events")
	}
}

func TestHighPriorityTxEvictsLowPriorityFrames(t *testing.T) {
	gatewayMac := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	vmMac := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	txQueueMaxBytes := 512
	stack := NewNetworkStack(NetworkStackOptions{
		GatewayIP:      "192.168.127.1",
		VmIP:           "192.168.127.3",
		GatewayMac:     gatewayMac,
		VmMac:          vmMac,
		DnsServers:     []string{"8.8.8.8"},
		TxQueueMaxBytes: txQueueMaxBytes,
		Callbacks:      NetworkCallbacks{},
	})

	for i := 0; i < 100; i++ {
		req := buildIcmpEchoRequest(1, uint16(i), bytes.Repeat([]byte{0xbb}, 16))
		packet := buildIPv4Packet([]byte{192, 168, 127, 3}, []byte{192, 168, 127, 1}, ipProtoICMP, req)
		frame := buildEthernetFrame(gatewayMac, vmMac, ethPIP, packet)
		stack.WriteToNetwork(qemuPacketFromFrame(frame))
	}

	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], vmMac)
	copy(arp[14:18], []byte{192, 168, 127, 3})
	copy(arp[24:28], []byte{192, 168, 127, 1})

	arpFrame := buildEthernetFrame(gatewayMac, vmMac, ethPARP, arp)
	stack.WriteToNetwork(qemuPacketFromFrame(arpFrame))

	tx := drainAllQemuTx(t, stack)
	if len(tx) > txQueueMaxBytes {
		t.Fatalf("tx length %d exceeds cap %d", len(tx), txQueueMaxBytes)
	}
	frames, err := decodeFramesFromQemuData(tx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	etherTypes := make([]uint16, 0, len(frames))
	for _, f := range frames {
		etherTypes = append(etherTypes, parseEthernet(f).etherType)
	}
	foundArp := false
	for _, et := range etherTypes {
		if et == ethPARP {
			foundArp = true
			break
		}
	}
	if !foundArp {
		t.Fatalf("expected arp reply to be present")
	}
}
