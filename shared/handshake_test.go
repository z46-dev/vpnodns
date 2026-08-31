package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientHelloRoundTrip(t *testing.T) {
	var (
		hello   ClientHello
		parsed  ClientHello
		message Message
		err     error
	)

	hello, err = NewClientHello("user", "pass", []CipherSuite{CipherSuiteCHACHA20POLY1305, CipherSuiteAES256GCM})
	require.NoError(t, err)
	require.Len(t, hello.Nonce, 32)

	message, err = hello.ToMessage(1, 2)
	require.NoError(t, err)
	parsed, err = ParseClientHello(message)
	require.NoError(t, err)
	assert.Equal(t, hello, parsed)
	assert.Equal(t, uint32(1), message.SessionID)
	assert.Equal(t, uint32(2), message.Sequence)
}

func TestHandshakeMessagesRoundTrip(t *testing.T) {
	var (
		serverHello ServerHello = ServerHello{
			Accepted:          true,
			SelectedCipher:    CipherSuiteAES128GCM,
			Nonce:             []byte("nonce"),
			SupportsFragments: true,
		}
		finished Finished = Finished{Proof: []byte("proof")}
		message  Message
		err      error
	)

	message, err = serverHello.ToMessage(3, 4)
	require.NoError(t, err)
	var parsedHello ServerHello
	parsedHello, err = ParseServerHello(message)
	require.NoError(t, err)
	assert.Equal(t, serverHello, parsedHello)

	message, err = finished.ToMessage(5, 6)
	require.NoError(t, err)
	var parsedFinished Finished
	parsedFinished, err = ParseFinished(message)
	require.NoError(t, err)
	assert.Equal(t, finished, parsedFinished)
}

func TestHandshakeParsingRejectsWrongTypeAndMalformedJSON(t *testing.T) {
	var (
		wrongType Message = Message{Type: MessageTypeClientPoll, Payload: []byte("{}")}
		malformed Message = Message{Type: MessageTypeClientHello, Payload: []byte("{")}
		err       error
	)

	_, err = ParseClientHello(wrongType)
	assert.Error(t, err)
	_, err = ParseServerHello(wrongType)
	assert.Error(t, err)
	_, err = ParseFinished(wrongType)
	assert.Error(t, err)
	_, err = ParseClientHello(malformed)
	assert.ErrorContains(t, err, "decode client hello")
}
