package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/z46-dev/vpnodns/shared"
)

type responseRecorder struct {
	message *dns.Msg
}

func (r *responseRecorder) LocalAddr() net.Addr                   { return &net.UDPAddr{} }
func (r *responseRecorder) RemoteAddr() net.Addr                  { return &net.UDPAddr{} }
func (r *responseRecorder) TsigStatus() error                     { return nil }
func (r *responseRecorder) TsigTimersOnly(bool)                   {}
func (r *responseRecorder) Hijack()                               {}
func (r *responseRecorder) Close() error                          { return nil }
func (r *responseRecorder) Write(data []byte) (int, error)        { return len(data), nil }
func (r *responseRecorder) WriteMsg(message *dns.Msg) (err error) { r.message = message; return }

func TestRouteFlagAndChooseCipher(t *testing.T) {
	var routes routeFlag
	require.NoError(t, routes.Set(" 10.0.0.0/8 "))
	require.NoError(t, routes.Set(""))
	assert.Equal(t, "10.0.0.0/8", routes.String())
	assert.Equal(t, shared.CipherSuiteAES256GCM, chooseCipher([]shared.CipherSuite{shared.CipherSuiteAES256GCM}))
	assert.Equal(t, shared.CipherSuiteCHACHA20POLY1305, chooseCipher(nil))
}

func TestHandleQueryClientHello(t *testing.T) {
	var (
		hello    shared.ClientHello
		message  shared.Message
		query    *dns.Msg
		response shared.Message
		err      error
	)

	hello, err = shared.NewClientHello("user", "pass", []shared.CipherSuite{shared.CipherSuiteAES128GCM})
	require.NoError(t, err)
	message, err = hello.ToMessage(10, 20)
	require.NoError(t, err)
	query, err = shared.EncodeQuery(message, "vpn.test")
	require.NoError(t, err)
	query.SetEdns0(1232, false)

	var recorder *responseRecorder = new(responseRecorder)
	err = handleQuery(recorder, query, "vpn.test", shared.NewReassembler(), nil, make(chan []byte))
	require.NoError(t, err)
	response, err = shared.DecodeTXTResponse(recorder.message)
	require.NoError(t, err)
	assert.Equal(t, shared.MessageTypeServerHello, response.Type)
	assert.Equal(t, uint32(21), response.Sequence)
	assert.Equal(t, uint16(1232), recorder.message.IsEdns0().UDPSize())
}

func TestHandleQueryPollAndUnhandledType(t *testing.T) {
	var (
		message  shared.Message = shared.Message{Type: shared.MessageTypeClientPoll, SessionID: 1, Sequence: 2}
		query    *dns.Msg
		response shared.Message
		err      error
	)

	query, err = shared.EncodeQuery(message, "vpn.test")
	require.NoError(t, err)
	var recorder *responseRecorder = new(responseRecorder)
	err = handleQuery(recorder, query, "vpn.test", shared.NewReassembler(), nil, make(chan []byte))
	require.NoError(t, err)
	response, err = shared.DecodeTXTResponse(recorder.message)
	require.NoError(t, err)
	assert.Equal(t, shared.MessageTypeServerAck, response.Type)

	message.Type = shared.MessageTypeServerData
	query, err = shared.EncodeQuery(message, "vpn.test")
	require.NoError(t, err)
	err = handleQuery(recorder, query, "vpn.test", shared.NewReassembler(), nil, make(chan []byte))
	assert.ErrorContains(t, err, "unhandled message type")
}

func TestEnqueueOutboundDropsOldest(t *testing.T) {
	var outbound chan []byte = make(chan []byte, 1)
	enqueueOutbound(outbound, []byte("old"))
	enqueueOutbound(outbound, []byte("new"))
	assert.Equal(t, []byte("new"), <-outbound)
}
