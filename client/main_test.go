package main

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/z46-dev/vpnodns/shared"
)

func TestRouteFlag(t *testing.T) {
	var routes routeFlag

	assert.NoError(t, routes.Set(" 10.0.0.0/8 "))
	assert.NoError(t, routes.Set(" "))
	assert.Equal(t, routeFlag{"10.0.0.0/8"}, routes)
	assert.Equal(t, "10.0.0.0/8", routes.String())
}

func TestTypeAllowed(t *testing.T) {
	assert.True(t, typeAllowed(shared.MessageTypeServerAck, []shared.MessageType{shared.MessageTypeServerData, shared.MessageTypeServerAck}))
	assert.False(t, typeAllowed(shared.MessageTypeFinished, nil))
}

func TestEnsureEDNS(t *testing.T) {
	var message *dns.Msg = new(dns.Msg)
	message.SetQuestion("vpn.test.", dns.TypeTXT)

	ensureEDNS(message, 0)
	assert.Equal(t, uint16(4096), message.IsEdns0().UDPSize())

	ensureEDNS(message, 2048)
	assert.Equal(t, uint16(4096), message.IsEdns0().UDPSize())

	message.IsEdns0().SetUDPSize(512)
	ensureEDNS(message, 2048)
	assert.Equal(t, uint16(2048), message.IsEdns0().UDPSize())
}
