package shared

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
)

const (
	CipherSuiteCHACHA20POLY1305 CipherSuite = "TLS_CHACHA20_POLY1305_SHA256"
	CipherSuiteAES256GCM        CipherSuite = "TLS_AES_256_GCM_SHA384"
	CipherSuiteAES128GCM        CipherSuite = "TLS_AES_128_GCM_SHA256"
)

type (
	// CipherSuite represents a supported cipher suite for the lightweight handshake.
	CipherSuite string

	ClientHello struct {
		Username     string        `json:"username"`
		Nonce        []byte        `json:"nonce"`
		Proof        []byte        `json:"proof"`
		CipherSuites []CipherSuite `json:"cipher_suites"`
	}

	ServerHello struct {
		Accepted          bool        `json:"accepted"`
		SelectedCipher    CipherSuite `json:"selected_cipher"`
		Nonce             []byte      `json:"nonce"`
		RejectionReason   string      `json:"reason,omitempty"`
		SupportsFragments bool        `json:"supports_fragments"`
	}

	Finished struct {
		Proof []byte `json:"proof"`
	}
)

func NewClientHello(username, password string, suites []CipherSuite) (hello ClientHello, err error) {
	var nonce []byte = make([]byte, 32)

	if _, err = rand.Read(nonce); err != nil {
		err = fmt.Errorf("generate client nonce: %w", err)
		return
	}

	hello = ClientHello{
		Username:     username,
		Nonce:        nonce,
		CipherSuites: suites,
	}

	hello.Proof = clientHelloProof(username, password, nonce)
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

// VerifyClientHello authenticates a client hello without transmitting the password.
func VerifyClientHello(hello ClientHello, username, password string) (valid bool) {
	if hello.Username != username || len(hello.Nonce) != 32 || len(hello.Proof) == 0 {
		return
	}

	valid = hmac.Equal(hello.Proof, clientHelloProof(username, password, hello.Nonce))
	return
}

// NewNonce creates a fresh nonce for handshake key material.
func NewNonce() (nonce []byte, err error) {
	nonce = make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		err = fmt.Errorf("generate nonce: %w", err)
	}

	return
}

func clientHelloProof(username, password string, nonce []byte) (proof []byte) {
	var mac hash.Hash = hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte("vpnodns client hello\x00"))
	_, _ = mac.Write([]byte(username))
	_, _ = mac.Write(nonce)
	proof = mac.Sum(nil)
	return
}

func ParseClientHello(msg Message) (hello ClientHello, err error) {
	if msg.Type != MessageTypeClientHello {
		err = fmt.Errorf("expected client hello, got %d", msg.Type)
		return
	}

	if err = json.Unmarshal(msg.Payload, &hello); err != nil {
		err = fmt.Errorf("decode client hello: %w", err)
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
	}

	return
}
