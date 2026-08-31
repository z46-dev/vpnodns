package shared

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFragmentationReassemblesOutOfOrder(t *testing.T) {
	var (
		original  Message = Message{Type: MessageTypeClientData, SessionID: 3, Sequence: 9, Payload: bytes.Repeat([]byte("fragment"), 200)}
		fragments []Message
		assembled Message
		done      bool
		err       error
	)

	fragments, err = SplitMessageForQuery(original, "vpn.test")
	require.NoError(t, err)
	require.Greater(t, len(fragments), 1)

	var reassembler *Reassembler = NewReassembler()
	for index := len(fragments) - 1; index >= 0; index-- {
		assembled, done, err = reassembler.Add(fragments[index])
		require.NoError(t, err)
	}

	assert.True(t, done)
	assert.Equal(t, original.Payload, assembled.Payload)
}

func TestReassemblerHandlesSingleDuplicateAndInvalidFragments(t *testing.T) {
	var reassembler *Reassembler = NewReassembler()
	var (
		message   Message = Message{Type: MessageTypeClientData, SessionID: 1, Sequence: 2, TotalParts: 2, Payload: []byte("a")}
		assembled Message
		done      bool
		err       error
	)

	assembled, done, err = reassembler.Add(Message{Type: MessageTypeFinished, Payload: []byte("single")})
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, uint16(1), assembled.TotalParts)

	_, _, err = reassembler.Add(Message{TotalParts: 2, Part: 2})
	assert.ErrorIs(t, err, ErrInvalidMessage)

	_, done, err = reassembler.Add(message)
	require.NoError(t, err)
	assert.False(t, done)
	_, done, err = reassembler.Add(message)
	require.NoError(t, err)
	assert.False(t, done)

	message.Type = MessageTypeClientPoll
	message.TotalParts = 3
	message.Part = 1
	_, _, err = reassembler.Add(message)
	assert.ErrorContains(t, err, "fragment mismatch")
}

func TestSplitMessageForQuerySinglePartAndImpossibleDomain(t *testing.T) {
	var (
		message   Message = Message{Type: MessageTypeClientPoll, TotalParts: 9, Part: 8, Payload: []byte("small")}
		fragments []Message
		err       error
	)

	fragments, err = SplitMessageForQuery(message, "vpn.test")
	require.NoError(t, err)
	require.Len(t, fragments, 1)
	assert.Equal(t, uint16(1), fragments[0].TotalParts)
	assert.Zero(t, fragments[0].Part)

	_, err = SplitMessageForQuery(message, string(bytes.Repeat([]byte("a"), MaxDNSWireLength)))
	assert.ErrorContains(t, err, "leaves no room")
}
