package shared

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionCryptoRoundTrip(t *testing.T) {
	var (
		clientNonce, serverNonce, key []byte = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), nil
		sealed, opened                Message
		err                           error
		message                       Message = Message{Type: MessageTypeClientData, SessionID: 7, Sequence: 9, Payload: []byte("secret packet")}
	)

	key, err = DeriveSessionKey("password", clientNonce, serverNonce)
	require.NoError(t, err)
	sealed, err = SealMessage(key, message)
	require.NoError(t, err)
	assert.NotEqual(t, message.Payload, sealed.Payload)
	opened, err = OpenMessage(key, sealed)
	require.NoError(t, err)
	assert.Equal(t, message, opened)
}

func TestSessionCryptoRejectsTampering(t *testing.T) {
	var (
		key     []byte  = bytes.Repeat([]byte{3}, SessionKeySize)
		message Message = Message{Type: MessageTypeClientPoll, SessionID: 1, Sequence: 2}
		sealed  Message
		err     error
	)

	sealed, err = SealMessage(key, message)
	require.NoError(t, err)
	sealed.Sequence++
	_, err = OpenMessage(key, sealed)
	assert.ErrorContains(t, err, "authenticate payload")

	var proof []byte
	proof, err = FinishedProof(key)
	require.NoError(t, err)
	assert.True(t, VerifyFinishedProof(key, proof))
	proof[0] ^= 1
	assert.False(t, VerifyFinishedProof(key, proof))
}

func TestSessionKeyRotationEpochs(t *testing.T) {
	var (
		key     []byte  = bytes.Repeat([]byte{4}, SessionKeySize)
		message Message = Message{Type: MessageTypeClientData, SessionID: 1, Sequence: KeyRotationSpan - 1, Payload: []byte("packet")}
		sealed  Message
		opened  Message
		err     error
	)

	sealed, err = SealMessage(key, message)
	require.NoError(t, err)
	opened, err = OpenMessage(key, sealed)
	require.NoError(t, err)
	assert.Equal(t, message, opened)

	message.Sequence = KeyRotationSpan
	sealed, err = SealMessage(key, message)
	require.NoError(t, err)
	opened, err = OpenMessage(key, sealed)
	require.NoError(t, err)
	assert.Equal(t, message, opened)
}
