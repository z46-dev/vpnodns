package tests

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/z46-dev/vpnodns/shared"
)

func TestMessageMarshalRoundTrip(t *testing.T) {
	var (
		orig shared.Message = shared.Message{
			Type:       shared.MessageTypeClientData,
			SessionID:  0xDEADBEEF,
			Sequence:   42,
			TotalParts: 3,
			Part:       1,
			Payload:    bytes.Repeat([]byte{0xab, 0xcd}, 100),
		}
		wire []byte
		err  error
	)

	wire, err = orig.MarshalBinary()
	assert.NoError(t, err)

	var got shared.Message
	got, err = shared.UnmarshalMessage(wire)
	assert.NoError(t, err)

	assert.Equal(t, orig.Type, got.Type)
	assert.Equal(t, orig.SessionID, got.SessionID)
	assert.Equal(t, orig.Sequence, got.Sequence)
	assert.Equal(t, orig.TotalParts, got.TotalParts)
	assert.Equal(t, orig.Part, got.Part)
	assert.Equal(t, orig.Payload, got.Payload)
}

func TestMarshalRejectsOversize(t *testing.T) {
	var (
		msg shared.Message = shared.Message{
			Type:    shared.MessageTypeClientData,
			Payload: bytes.Repeat([]byte("z"), shared.MaxPayloadSize+1),
		}
		err error
	)

	_, err = msg.MarshalBinary()
	assert.Error(t, err)
}

func TestDNSQueryRoundTrip(t *testing.T) {
	var (
		orig shared.Message = shared.Message{
			Type:      shared.MessageTypeClientPoll,
			SessionID: 0x12345678,
			Sequence:  7,
			Payload:   []byte("hello-world"),
		}
		query   *dns.Msg
		err     error
		decoded shared.Message
	)

	query, err = shared.EncodeQuery(orig, "vpn.test")
	assert.NoError(t, err)

	decoded, err = shared.DecodeQuery(query, "vpn.test")
	assert.NoError(t, err)

	assert.Equal(t, orig.Type, decoded.Type)
	assert.Equal(t, orig.SessionID, decoded.SessionID)
	assert.Equal(t, orig.Sequence, decoded.Sequence)
	assert.Equal(t, orig.Payload, decoded.Payload)
}

func TestTXTResponseRoundTrip(t *testing.T) {
	var (
		orig shared.Message = shared.Message{
			Type:      shared.MessageTypeServerData,
			SessionID: 0xBEADFEED,
			Sequence:  10,
			Payload:   []byte("response"),
		}
		req, respMsg *dns.Msg
		err          error
		decoded      shared.Message
	)

	req, err = shared.EncodeQuery(orig, "vpn.test")
	assert.NoError(t, err)

	respMsg, err = shared.EncodeTXTResponse(orig, req)
	assert.NoError(t, err)

	decoded, err = shared.DecodeTXTResponse(respMsg)
	assert.NoError(t, err)

	assert.Equal(t, orig.Type, decoded.Type)
	assert.Equal(t, orig.Payload, decoded.Payload)
}

func TestDNSQueryFragmentationRoundTrip(t *testing.T) {
	var (
		orig shared.Message = shared.Message{
			Type:      shared.MessageTypeClientPoll,
			SessionID: 0x87654321,
			Sequence:  9,
			Payload:   bytes.Repeat([]byte("fragment-me"), 150),
		}
		fragments []shared.Message
		err       error
	)

	fragments, err = shared.SplitMessageForQuery(orig, "vpn.test")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(fragments), 2)

	var (
		assembler *shared.Reassembler = shared.NewReassembler()
		final     shared.Message
	)

	for idx := 0; idx < len(fragments); idx++ {
		var (
			part  shared.Message = fragments[idx]
			query *dns.Msg
		)

		query, err = shared.EncodeQuery(part, "vpn.test")
		assert.NoError(t, err)

		_, err = query.Pack()
		assert.NoError(t, err)

		var decoded shared.Message
		decoded, err = shared.DecodeQuery(query, "vpn.test")
		assert.NoError(t, err)

		var (
			result shared.Message
			done   bool
		)

		result, done, err = assembler.Add(decoded)
		assert.NoError(t, err)
		if done {
			final = result
		}
	}

	assert.Greater(t, len(final.Payload), 0)
	assert.Equal(t, orig.Payload, final.Payload)
}

func TestEncodeQueryRejectsOversize(t *testing.T) {
	var (
		msg shared.Message = shared.Message{
			Type:      shared.MessageTypeClientPoll,
			SessionID: 1,
			Sequence:  1,
			Payload:   bytes.Repeat([]byte("x"), shared.MaxQueryPayload("vpn.test")+1),
		}
		err error
	)

	_, err = shared.EncodeQuery(msg, "vpn.test")
	assert.Error(t, err)
}

func TestReassemblerMismatch(t *testing.T) {
	var (
		assembler *shared.Reassembler = shared.NewReassembler()
		first     shared.Message      = shared.Message{
			Type:       shared.MessageTypeClientData,
			SessionID:  1,
			Sequence:   1,
			TotalParts: 2,
			Part:       0,
			Payload:    []byte("hello"),
		}
		second shared.Message = shared.Message{
			Type:       shared.MessageTypeClientPoll,
			SessionID:  1,
			Sequence:   1,
			TotalParts: 3,
			Part:       1,
			Payload:    []byte("bad"),
		}
		err error
	)

	_, _, err = assembler.Add(first)
	assert.NoError(t, err)

	_, _, err = assembler.Add(second)
	assert.Error(t, err)
}

func TestIsMulticastAndSummary(t *testing.T) {
	var v4multicast []byte = []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0xff, 0x11, 0x00, 0x00,
		192, 0, 2, 1,
		224, 0, 0, 1,
		0x00, 0x35, 0x00, 0x35,
	}

	assert.True(t, shared.IsMulticast(v4multicast))

	var summary string = shared.PacketSummary(v4multicast)
	assert.NotEmpty(t, summary)

	var v4unicast []byte = []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x06, 0x11, 0x00, 0x00,
		203, 0, 113, 5,
		198, 51, 100, 9,
		0x00, 0x50, 0x01, 0xbb,
	}

	assert.False(t, shared.IsMulticast(v4unicast))
	assert.NotEmpty(t, shared.PacketSummary(v4unicast))
}
