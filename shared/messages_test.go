package shared

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageMarshalRoundTrip(t *testing.T) {
	var original Message = Message{
		Type:       MessageTypeClientData,
		SessionID:  0xDEADBEEF,
		Sequence:   42,
		TotalParts: 3,
		Part:       1,
		Payload:    bytes.Repeat([]byte{0xab, 0xcd}, 100),
	}

	var (
		wire []byte
		err  error
	)

	wire, err = original.MarshalBinary()
	require.NoError(t, err)

	var decoded Message
	decoded, err = UnmarshalMessage(wire)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestMessageRejectsInvalidLengths(t *testing.T) {
	var (
		message Message = Message{Payload: bytes.Repeat([]byte("z"), MaxPayloadSize+1)}
		wire    []byte  = make([]byte, messageHeaderSize)
		err     error
	)

	_, err = message.MarshalBinary()
	assert.ErrorIs(t, err, ErrPayloadTooLarge)

	_, err = UnmarshalMessage(wire[:messageHeaderSize-1])
	assert.ErrorIs(t, err, ErrInvalidMessage)

	wire[13], wire[14] = 0, 1
	_, err = UnmarshalMessage(wire)
	assert.ErrorIs(t, err, ErrIncompletePayload)
}

func TestUnmarshalMessageIgnoresTrailingBytes(t *testing.T) {
	var (
		wire    []byte
		decoded Message
		err     error
	)

	wire, err = (Message{Type: MessageTypeFinished, Payload: []byte("ok")}).MarshalBinary()
	require.NoError(t, err)
	wire = append(wire, []byte("trailing")...)

	decoded, err = UnmarshalMessage(wire)
	require.NoError(t, err)
	assert.Equal(t, []byte("ok"), decoded.Payload)
	assert.False(t, errors.Is(err, ErrIncompletePayload))
}
