package shared

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSQueryRoundTrip(t *testing.T) {
	var original Message = Message{Type: MessageTypeClientPoll, SessionID: 7, Sequence: 8, Payload: []byte("hello")}
	var (
		query   *dns.Msg
		decoded Message
		err     error
	)

	query, err = EncodeQuery(original, ".VPN.Test.")
	require.NoError(t, err)
	decoded, err = DecodeQuery(query, "vpn.test")
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
	assert.Equal(t, uint16(dns.TypeTXT), query.Question[0].Qtype)
}

func TestDecodeQueryRejectsMalformedInput(t *testing.T) {
	var (
		query *dns.Msg = new(dns.Msg)
		err   error
	)

	_, err = DecodeQuery(nil, "vpn.test")
	assert.ErrorContains(t, err, "missing question")
	_, err = DecodeQuery(query, "vpn.test")
	assert.ErrorContains(t, err, "missing question")

	query.SetQuestion("not-base32.other.test.", dns.TypeTXT)
	_, err = DecodeQuery(query, "vpn.test")
	assert.ErrorContains(t, err, "unexpected domain")

	query.SetQuestion("***.vpn.test.", dns.TypeTXT)
	_, err = DecodeQuery(query, "vpn.test")
	assert.ErrorContains(t, err, "decode base32")

	query.SetQuestion("vpn.test.", dns.TypeTXT)
	_, err = DecodeQuery(query, "vpn.test")
	assert.ErrorContains(t, err, "no encoded labels")
}

func TestTXTResponseRoundTripAndValidation(t *testing.T) {
	var (
		original Message = Message{Type: MessageTypeServerData, Payload: bytes.Repeat([]byte("response"), 100)}
		request  *dns.Msg
		response *dns.Msg
		decoded  Message
		err      error
	)

	request, err = EncodeQuery(Message{Type: MessageTypeClientPoll}, "vpn.test")
	require.NoError(t, err)
	response, err = EncodeTXTResponse(original, request)
	require.NoError(t, err)
	require.Greater(t, len(response.Answer[0].(*dns.TXT).Txt), 1)
	decoded, err = DecodeTXTResponse(response)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)

	_, err = DecodeTXTResponse(nil)
	assert.ErrorContains(t, err, "missing answer")
	response.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: "vpn.test."}}
	_, err = DecodeTXTResponse(response)
	assert.ErrorContains(t, err, "unexpected answer type")
}

func TestDNSLengthHelpers(t *testing.T) {
	var (
		message Message = Message{Type: MessageTypeClientData, Payload: bytes.Repeat([]byte("x"), MaxQueryPayload("vpn.test")+1)}
		err     error
	)

	_, err = EncodeQuery(message, "vpn.test")
	assert.ErrorIs(t, err, ErrNameTooLong)
	_, err = EncodeQuery(Message{Type: MessageTypeClientPoll}, string(bytes.Repeat([]byte("a"), maxLabelLength+1)))
	assert.ErrorIs(t, err, ErrNameTooLong)
	assert.Nil(t, chunkString("abc", 0))
	assert.Equal(t, []string{"ab", "c"}, chunkString("abc", 2))
}
