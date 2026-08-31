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

func (r *responseRecorder) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (r *responseRecorder) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (r *responseRecorder) TsigStatus() error {
	return nil
}

func (r *responseRecorder) TsigTimersOnly(bool) {}

func (r *responseRecorder) Hijack() {}

func (r *responseRecorder) Close() error {
	return nil
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return len(data), nil
}

func (r *responseRecorder) WriteMsg(message *dns.Msg) (err error) {
	r.message = message
	return
}

func handleTestMessage(t *testing.T, message shared.Message, username, password string, sessions *authSessions) (recorder *responseRecorder) {
	t.Helper()
	var (
		assembler *shared.Reassembler = shared.NewReassembler()
		fragments []shared.Message
		err       error
	)

	fragments, err = shared.SplitMessageForQuery(message, "vpn.test")
	require.NoError(t, err)
	recorder = new(responseRecorder)

	for _, fragment := range fragments {
		var query *dns.Msg
		query, err = shared.EncodeQuery(fragment, "vpn.test")
		require.NoError(t, err)

		err = handleQuery(recorder, query, "vpn.test", username, password, assembler, sessions, nil, make(chan []byte))
		require.NoError(t, err)
	}

	return
}

func TestRouteFlagAndChooseCipher(t *testing.T) {
	var routes routeFlag
	require.NoError(t, routes.Set(" 10.0.0.0/8 "))
	require.NoError(t, routes.Set(""))
	assert.Equal(t, "10.0.0.0/8", routes.String())
	assert.Equal(t, shared.CipherSuiteAES256GCM, chooseCipher([]shared.CipherSuite{shared.CipherSuiteAES128GCM, shared.CipherSuiteAES256GCM}))
	assert.Empty(t, chooseCipher(nil))
}

func TestHandleQueryClientHello(t *testing.T) {
	var (
		hello    shared.ClientHello
		message  shared.Message
		response shared.Message
		err      error
	)

	hello, err = shared.NewClientHello("user", "pass", []shared.CipherSuite{shared.CipherSuiteAES256GCM})
	require.NoError(t, err)

	message, err = hello.ToMessage(10, 20)
	require.NoError(t, err)

	var recorder *responseRecorder = handleTestMessage(t, message, "user", "pass", newAuthSessions())
	response, err = shared.DecodeTXTResponse(recorder.message)
	require.NoError(t, err)

	assert.Equal(t, shared.MessageTypeServerHello, response.Type)
	assert.Equal(t, uint32(21), response.Sequence)
	assert.Equal(t, uint16(4096), recorder.message.IsEdns0().UDPSize())
}

func TestHandleQueryRejectsInvalidCredentials(t *testing.T) {
	var (
		hello    shared.ClientHello
		message  shared.Message
		response shared.Message
		err      error
	)

	hello, err = shared.NewClientHello("user", "wrong", nil)
	require.NoError(t, err)
	message, err = hello.ToMessage(10, 20)
	require.NoError(t, err)

	var (
		sessions *authSessions     = newAuthSessions()
		recorder *responseRecorder = handleTestMessage(t, message, "user", "pass", sessions)
	)

	response, err = shared.DecodeTXTResponse(recorder.message)
	require.NoError(t, err)

	var rejection shared.ServerHello
	rejection, err = shared.ParseServerHello(response)
	require.NoError(t, err)

	assert.False(t, rejection.Accepted)
	assert.Equal(t, "invalid credentials", rejection.RejectionReason)
	_, authorized := sessions.key(message.SessionID)
	assert.False(t, authorized)
}

func TestHandleQueryPollAndUnhandledType(t *testing.T) {
	var (
		message shared.Message = shared.Message{Type: shared.MessageTypeClientPoll, SessionID: 1, Sequence: 2}
		query   *dns.Msg
		err     error
	)

	query, err = shared.EncodeQuery(message, "vpn.test")
	require.NoError(t, err)

	var recorder *responseRecorder = new(responseRecorder)
	err = handleQuery(recorder, query, "vpn.test", "user", "pass", shared.NewReassembler(), newAuthSessions(), nil, make(chan []byte))
	assert.ErrorContains(t, err, "unauthenticated or expired session")

	message.Type = shared.MessageTypeServerData
	query, err = shared.EncodeQuery(message, "vpn.test")
	require.NoError(t, err)
	err = handleQuery(recorder, query, "vpn.test", "user", "pass", shared.NewReassembler(), newAuthSessions(), nil, make(chan []byte))
	assert.ErrorContains(t, err, "unhandled message type")
}

func TestEnqueueOutboundDropsOldest(t *testing.T) {
	var outbound chan []byte = make(chan []byte, 1)
	enqueueOutbound(outbound, []byte("old"))
	enqueueOutbound(outbound, []byte("new"))
	assert.Equal(t, []byte("new"), <-outbound)
}
