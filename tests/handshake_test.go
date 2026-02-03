package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/z46-dev/vpnodns/shared"
)

func TestClientHelloRoundTrip(t *testing.T) {
	const password = "pass"
	var hello shared.ClientHello
	var err error

	hello, err = shared.NewClientHello("user", password, []shared.CipherSuite{
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
	assert.Equal(t, hello.Nonce, parsed.Nonce)
	assert.Equal(t, hello.Proof, parsed.Proof)
	assert.Equal(t, len(hello.CipherSuites), len(parsed.CipherSuites))
	assert.True(t, shared.VerifyClientHelloProof(parsed, password))
}

func TestServerHelloRoundTrip(t *testing.T) {
	var hello shared.ServerHello = shared.ServerHello{
		Accepted:          true,
		SelectedCipher:    shared.CipherSuiteCHACHA20POLY1305,
		Nonce:             []byte("nonce"),
		Proof:             []byte("proof"),
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
	assert.Equal(t, hello.Proof, parsed.Proof)
	assert.Equal(t, hello.SupportsFragments, parsed.SupportsFragments)
}

func TestFinishedRoundTrip(t *testing.T) {
	var finished shared.Finished = shared.NewFinished([]byte("01234567890123456789012345678901"), 9)

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
	assert.True(t, shared.VerifyFinished(parsed, []byte("01234567890123456789012345678901"), 9))
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

func TestDeriveSessionKeyDeterministic(t *testing.T) {
	key1, err := shared.DeriveSessionKey("pass", 100, []byte("client"), []byte("server"))
	assert.NoError(t, err)
	key2, err := shared.DeriveSessionKey("pass", 100, []byte("client"), []byte("server"))
	assert.NoError(t, err)
	assert.Equal(t, key1, key2)
}
