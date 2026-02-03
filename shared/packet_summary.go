package shared

import (
	"encoding/binary"
	"fmt"
	"net"
)

// PacketSummary returns a short human-readable description of a raw IP packet.
func PacketSummary(pkt []byte) (summary string) {
	if len(pkt) == 0 {
		return "empty"
	}

	switch pkt[0] >> 4 {
	case 4:
		summary = summarizeIPv4(pkt)
		return
	case 6:
		summary = summarizeIPv6(pkt)
		return
	default:
		summary = fmt.Sprintf("unknown version (%d)", pkt[0]>>4)
		return
	}
}

func summarizeIPv4(pkt []byte) (summary string) {
	const ipv4HeaderMin = 20
	if len(pkt) < ipv4HeaderMin {
		return "ipv4 (truncated)"
	}

	var ihl int = int(pkt[0]&0x0F) * 4
	if ihl < ipv4HeaderMin || len(pkt) < ihl {
		return "ipv4 (bad ihl)"
	}

	var proto byte = pkt[9]
	var src net.IP = net.IP(pkt[12:16])
	var dst net.IP = net.IP(pkt[16:20])

	summary = fmt.Sprintf("ipv4/%s %s > %s", protoName(proto), src, dst)

	if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
		var sport uint16 = binary.BigEndian.Uint16(pkt[ihl:])
		var dport uint16 = binary.BigEndian.Uint16(pkt[ihl+2:])
		summary = summary + fmt.Sprintf(" %d > %d", sport, dport)
	}

	return summary
}

func summarizeIPv6(pkt []byte) (summary string) {
	const ipv6HeaderLen = 40
	if len(pkt) < ipv6HeaderLen {
		return "ipv6 (truncated)"
	}

	var next byte = pkt[6]
	var src net.IP = net.IP(pkt[8:24])
	var dst net.IP = net.IP(pkt[24:40])

	summary = fmt.Sprintf("ipv6/%s %s > %s", protoName(next), src, dst)

	if (next == 6 || next == 17) && len(pkt) >= ipv6HeaderLen+4 {
		var sport uint16 = binary.BigEndian.Uint16(pkt[ipv6HeaderLen:])
		var dport uint16 = binary.BigEndian.Uint16(pkt[ipv6HeaderLen+2:])
		summary = summary + fmt.Sprintf(" %d > %d", sport, dport)
	}

	return summary
}

func protoName(p byte) (name string) {
	switch p {
	case 1:
		name = "icmp"
		return
	case 6:
		name = "tcp"
		return
	case 17:
		name = "udp"
		return
	case 58:
		name = "icmpv6"
		return
	default:
		name = fmt.Sprintf("proto-%d", p)
		return
	}
}

// IsMulticast reports whether the packet's destination address is multicast.
func IsMulticast(pkt []byte) (multicast bool) {
	if len(pkt) == 0 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		var dst net.IP = net.IP(pkt[16:20])
		multicast = dst.IsMulticast()
		return
	case 6:
		if len(pkt) < 40 {
			return false
		}
		var dst net.IP = net.IP(pkt[24:40])
		multicast = dst.IsMulticast()
		return
	default:
		return false
	}
}

// PacketSrcDst extracts source and destination IPs from IPv4/IPv6 packets.
// ok is false when the packet is truncated or not an IP packet.
func PacketSrcDst(pkt []byte) (src net.IP, dst net.IP, ok bool) {
	if len(pkt) == 0 {
		return nil, nil, false
	}

	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return nil, nil, false
		}
		return net.IP(pkt[12:16]).To4(), net.IP(pkt[16:20]).To4(), true
	case 6:
		if len(pkt) < 40 {
			return nil, nil, false
		}
		return append(net.IP(nil), pkt[8:24]...), append(net.IP(nil), pkt[24:40]...), true
	default:
		return nil, nil, false
	}
}
