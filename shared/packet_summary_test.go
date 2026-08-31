package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPacketSummaryAndMulticast(t *testing.T) {
	var ipv4 []byte = []byte{0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 224, 0, 0, 1, 0, 53, 0, 54}
	var ipv6 []byte = make([]byte, 44)
	ipv6[0], ipv6[6], ipv6[24], ipv6[40], ipv6[42] = 0x60, 6, 0xff, 0, 1

	assert.Equal(t, "empty", PacketSummary(nil))
	assert.Equal(t, "unknown version (1)", PacketSummary([]byte{0x10}))
	assert.Equal(t, "ipv4 (truncated)", PacketSummary([]byte{0x40}))
	assert.Equal(t, "ipv4 (bad ihl)", PacketSummary(append([]byte{0x41}, make([]byte, 19)...)))
	assert.Contains(t, PacketSummary(ipv4), "53 > 54")
	assert.True(t, IsMulticast(ipv4))
	assert.Contains(t, PacketSummary(ipv6), "ipv6/tcp")
	assert.True(t, IsMulticast(ipv6))
	assert.False(t, IsMulticast(nil))
}
