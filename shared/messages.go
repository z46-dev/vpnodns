package shared

import (
	"encoding/binary"
	"errors"
	"math"
)

// MessageType identifies the role of a message flowing through DNS.
type MessageType uint8

const (
	MessageTypeClientHello MessageType = iota + 1
	MessageTypeServerHello
	MessageTypeFinished
	MessageTypeClientData
	MessageTypeClientPoll
	MessageTypeServerData
	MessageTypeServerAck
)

const (
	messageHeaderSize = 15 // 1(type) + 4(session) + 4(seq) + 2(totalParts) + 2(part) + 2(payloadLen)
	MaxPayloadSize    = math.MaxUint16
)

var (
	ErrPayloadTooLarge   error = errors.New("payload too large")
	ErrInvalidMessage    error = errors.New("invalid message")
	ErrUnsupportedType   error = errors.New("unsupported message type")
	ErrIncompletePayload error = errors.New("incomplete payload")
	ErrNameTooLong       error = errors.New("encoded name exceeds DNS limits")
)

// Message is the fundamental wire unit exchanged between client and server.
// When payloads exceed DNS limits, they are split into numbered parts.
type Message struct {
	Type                MessageType
	SessionID, Sequence uint32
	TotalParts, Part    uint16
	Payload             []byte
}

// MarshalBinary encodes the message into a deterministic binary form suitable for DNS transport.
func (m Message) MarshalBinary() (buf []byte, err error) {
	if len(m.Payload) > MaxPayloadSize {
		err = ErrPayloadTooLarge
		return
	}

	buf = make([]byte, messageHeaderSize+len(m.Payload))
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:], m.SessionID)
	binary.BigEndian.PutUint32(buf[5:], m.Sequence)
	binary.BigEndian.PutUint16(buf[9:], m.TotalParts)
	binary.BigEndian.PutUint16(buf[11:], m.Part)
	binary.BigEndian.PutUint16(buf[13:], uint16(len(m.Payload)))
	copy(buf[messageHeaderSize:], m.Payload)

	return
}

// UnmarshalMessage parses a binary message back into a Message structure.
func UnmarshalMessage(data []byte) (msg Message, err error) {
	if len(data) < messageHeaderSize {
		err = ErrInvalidMessage
		return
	}

	var payloadLen int = int(binary.BigEndian.Uint16(data[13:]))
	if len(data) < messageHeaderSize+payloadLen {
		err = ErrIncompletePayload
		return
	}

	msg = Message{
		Type:       MessageType(data[0]),
		SessionID:  binary.BigEndian.Uint32(data[1:]),
		Sequence:   binary.BigEndian.Uint32(data[5:]),
		TotalParts: binary.BigEndian.Uint16(data[9:]),
		Part:       binary.BigEndian.Uint16(data[11:]),
		Payload:    make([]byte, payloadLen),
	}

	copy(msg.Payload, data[messageHeaderSize:messageHeaderSize+payloadLen])
	return
}
