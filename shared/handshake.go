package shared

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// CipherSuite represents a supported cipher suite for the lightweight handshake.
type CipherSuite string

const (
	CipherSuiteCHACHA20POLY1305 CipherSuite = "TLS_CHACHA20_POLY1305_SHA256"
	CipherSuiteAES256GCM        CipherSuite = "TLS_AES_256_GCM_SHA384"
	CipherSuiteAES128GCM        CipherSuite = "TLS_AES_128_GCM_SHA256"
)

type ClientHello struct {
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	Nonce        []byte        `json:"nonce"`
	CipherSuites []CipherSuite `json:"cipher_suites"`
}

type ServerHello struct {
	Accepted          bool        `json:"accepted"`
	SelectedCipher    CipherSuite `json:"selected_cipher"`
	Nonce             []byte      `json:"nonce"`
	RejectionReason   string      `json:"reason,omitempty"`
	SupportsFragments bool        `json:"supports_fragments"`
}

type Finished struct {
	Proof []byte `json:"proof"`
}

func NewClientHello(username, password string, suites []CipherSuite) (hello ClientHello, err error) {
	var nonce []byte = make([]byte, 32)

	if _, err = rand.Read(nonce); err != nil {
		err = fmt.Errorf("generate client nonce: %w", err)
		return
	}

	hello = ClientHello{
		Username:     username,
		Password:     password,
		Nonce:        nonce,
		CipherSuites: suites,
	}
	return
}

func (h ClientHello) ToMessage(sessionID, seq uint32) (msg Message, err error) {
	var payload []byte

	if payload, err = json.Marshal(h); err != nil {
		err = fmt.Errorf("encode client hello: %w", err)
		return
	}

	msg = Message{
		Type:      MessageTypeClientHello,
		SessionID: sessionID,
		Sequence:  seq,
		Payload:   payload,
	}
	return
}

func ParseClientHello(msg Message) (hello ClientHello, err error) {
	if msg.Type != MessageTypeClientHello {
		err = fmt.Errorf("expected client hello, got %d", msg.Type)
		return
	}

	if err = json.Unmarshal(msg.Payload, &hello); err != nil {
		err = fmt.Errorf("decode client hello: %w", err)
		return
	}

	return
}

func (h ServerHello) ToMessage(sessionID, seq uint32) (msg Message, err error) {
	var payload []byte

	if payload, err = json.Marshal(h); err != nil {
		err = fmt.Errorf("encode server hello: %w", err)
		return
	}

	msg = Message{
		Type:      MessageTypeServerHello,
		SessionID: sessionID,
		Sequence:  seq,
		Payload:   payload,
	}
	return
}

func ParseServerHello(msg Message) (hello ServerHello, err error) {
	if msg.Type != MessageTypeServerHello {
		err = fmt.Errorf("expected server hello, got %d", msg.Type)
		return
	}

	if err = json.Unmarshal(msg.Payload, &hello); err != nil {
		err = fmt.Errorf("decode server hello: %w", err)
		return
	}

	return
}

func (f Finished) ToMessage(sessionID, seq uint32) (msg Message, err error) {
	var payload []byte

	if payload, err = json.Marshal(f); err != nil {
		err = fmt.Errorf("encode finished: %w", err)
		return
	}

	msg = Message{
		Type:      MessageTypeFinished,
		SessionID: sessionID,
		Sequence:  seq,
		Payload:   payload,
	}
	return
}

func ParseFinished(msg Message) (finished Finished, err error) {
	if msg.Type != MessageTypeFinished {
		err = fmt.Errorf("expected finished, got %d", msg.Type)
		return
	}

	if err = json.Unmarshal(msg.Payload, &finished); err != nil {
		err = fmt.Errorf("decode finished: %w", err)
		return
	}

	return
}
