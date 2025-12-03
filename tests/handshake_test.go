package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/z46-dev/vpnodns/shared"
)

func TestClientHelloRoundTrip(t *testing.T) {
	var hello shared.ClientHello
	var err error

	hello, err = shared.NewClientHello("user", "pass", []shared.CipherSuite{
		shared.CipherSuiteCHACHA20POLY1305,
		shared.CipherSuiteAES256GCM,
	})
	assert.NoError(t, err)

	var msg shared.Message
	msg, err = hello.ToMessage(1, 1)
	assert.NoError(t, err)

	var parsed shared.ClientHello
	parsed, err = shared.ParseClientHello(msg)
	assert.NoError(t, err)

	assert.Equal(t, hello.Username, parsed.Username)
	assert.Equal(t, hello.Password, parsed.Password)
	assert.Equal(t, hello.Nonce, parsed.Nonce)
	assert.Equal(t, len(hello.CipherSuites), len(parsed.CipherSuites))
}

func TestServerHelloRoundTrip(t *testing.T) {
	var hello shared.ServerHello = shared.ServerHello{
		Accepted:          true,
		SelectedCipher:    shared.CipherSuiteCHACHA20POLY1305,
		Nonce:             []byte("nonce"),
		SupportsFragments: true,
	}

	var (
		msg shared.Message
		err error
	)

	msg, err = hello.ToMessage(2, 3)
	assert.NoError(t, err)

	var parsed shared.ServerHello
	parsed, err = shared.ParseServerHello(msg)
	assert.NoError(t, err)

	assert.Equal(t, hello.Accepted, parsed.Accepted)
	assert.Equal(t, hello.SelectedCipher, parsed.SelectedCipher)
	assert.Equal(t, hello.Nonce, parsed.Nonce)
	assert.Equal(t, hello.SupportsFragments, parsed.SupportsFragments)
}

func TestFinishedRoundTrip(t *testing.T) {
	var finished shared.Finished = shared.Finished{Proof: []byte("proof-bytes")}

	var (
		msg shared.Message
		err error
	)

	msg, err = finished.ToMessage(9, 5)
	assert.NoError(t, err)

	var parsed shared.Finished
	parsed, err = shared.ParseFinished(msg)
	assert.NoError(t, err)

	assert.Equal(t, finished.Proof, parsed.Proof)
}

func TestHandshakeTypeValidation(t *testing.T) {
	var wrong shared.Message = shared.Message{
		Type:      shared.MessageTypeClientPoll,
		SessionID: 1,
		Sequence:  1,
		Payload:   []byte("{}"),
	}

	var (
		_   shared.ClientHello
		err error
	)

	_, err = shared.ParseClientHello(wrong)
	assert.Error(t, err)

	_, err = shared.ParseServerHello(wrong)
	assert.Error(t, err)

	_, err = shared.ParseFinished(wrong)
	assert.Error(t, err)
}
