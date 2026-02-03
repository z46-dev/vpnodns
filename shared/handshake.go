package shared

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
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
	Nonce        []byte        `json:"nonce"`
	Proof        []byte        `json:"proof"`
	CipherSuites []CipherSuite `json:"cipher_suites"`
}

type ServerHello struct {
	Accepted          bool        `json:"accepted"`
	SelectedCipher    CipherSuite `json:"selected_cipher"`
	Nonce             []byte      `json:"nonce"`
	Proof             []byte      `json:"proof"`
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
		Nonce:        nonce,
		Proof:        ComputeClientHelloProof(username, password, nonce),
		CipherSuites: suites,
	}
	return
}

func ComputeClientHelloProof(username, password string, nonce []byte) (proof []byte) {
	var mac hashWriter = newHMAC(password)
	mac.Write([]byte("vpnodns-client-hello"))
	mac.Write([]byte(username))
	mac.Write(nonce)
	return mac.Sum(nil)
}

func VerifyClientHelloProof(hello ClientHello, password string) (ok bool) {
	var expected []byte = ComputeClientHelloProof(hello.Username, password, hello.Nonce)
	return hmac.Equal(hello.Proof, expected)
}

func ComputeServerHelloProof(password string, sessionID uint32, clientNonce, serverNonce []byte) (proof []byte) {
	var mac hashWriter = newHMAC(password)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	mac.Write([]byte("vpnodns-server-hello"))
	mac.Write(sid[:])
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}

func VerifyServerHelloProof(hello ServerHello, password string, sessionID uint32, clientNonce []byte) (ok bool) {
	var expected []byte = ComputeServerHelloProof(password, sessionID, clientNonce, hello.Nonce)
	return hmac.Equal(hello.Proof, expected)
}

func DeriveSessionKey(password string, sessionID uint32, clientNonce, serverNonce []byte) (key []byte, err error) {
	var (
		sid  [4]byte
		info []byte = []byte("vpnodns-session-aead-key")
		salt []byte
	)

	binary.BigEndian.PutUint32(sid[:], sessionID)
	salt = append(append([]byte(nil), clientNonce...), serverNonce...)

	var reader io.Reader = hkdf.New(sha256.New, []byte(password), salt, append(info, sid[:]...))
	key = make([]byte, 32)
	if _, err = io.ReadFull(reader, key); err != nil {
		err = fmt.Errorf("derive session key: %w", err)
		return
	}
	return
}

func NewFinished(key []byte, sessionID uint32) (finished Finished) {
	var mac hashWriter = hmac.New(sha256.New, key)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	mac.Write([]byte("vpnodns-finished"))
	mac.Write(sid[:])
	finished.Proof = mac.Sum(nil)
	return
}

func VerifyFinished(f Finished, key []byte, sessionID uint32) (ok bool) {
	var expected Finished = NewFinished(key, sessionID)
	return hmac.Equal(f.Proof, expected.Proof)
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

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func newHMAC(password string) (h hashWriter) {
	return hmac.New(sha256.New, []byte(password))
}
