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
		summary = "ipv4 (truncated)"
		return
	}

	var ihl int = int(pkt[0]&0x0F) * 4
	if ihl < ipv4HeaderMin || len(pkt) < ihl {
		summary = "ipv4 (bad ihl)"
		return
	}

	var proto byte = pkt[9]

	summary = fmt.Sprintf("ipv4/%s %s > %s", protoName(proto), net.IP(pkt[12:16]), net.IP(pkt[16:20]))
	if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
		summary = summary + fmt.Sprintf(" %d > %d", binary.BigEndian.Uint16(pkt[ihl:]), binary.BigEndian.Uint16(pkt[ihl+2:]))
	}

	return
}

func summarizeIPv6(pkt []byte) (summary string) {
	const ipv6HeaderLen = 40
	if len(pkt) < ipv6HeaderLen {
		summary = "ipv6 (truncated)"
		return
	}

	var next byte = pkt[6]

	summary = fmt.Sprintf("ipv6/%s %s > %s", protoName(next), net.IP(pkt[8:24]), net.IP(pkt[24:40]))
	if (next == 6 || next == 17) && len(pkt) >= ipv6HeaderLen+4 {
		summary = summary + fmt.Sprintf(" %d > %d", binary.BigEndian.Uint16(pkt[ipv6HeaderLen:]), binary.BigEndian.Uint16(pkt[ipv6HeaderLen+2:]))
	}

	return
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
		multicast = false
		return
	}

	multicast = false
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) >= 20 {
			multicast = net.IP(pkt[16:20]).IsMulticast()
		}
	case 6:
		if len(pkt) >= 40 {
			multicast = net.IP(pkt[24:40]).IsMulticast()
		}
	default:
		multicast = false
	}

	return
}
