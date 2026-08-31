package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

const (
	SessionKeySize  = 32
	KeyRotationSpan = 1024
)

// DeriveSessionKey derives a session-specific key from the password and both handshake nonces.
func DeriveSessionKey(password string, clientNonce, serverNonce []byte) (key []byte, err error) {
	if password == "" || len(clientNonce) != 32 || len(serverNonce) != 32 {
		err = fmt.Errorf("invalid session key material")
		return
	}

	var mac hash.Hash = hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte("vpnodns session key\x00"))
	_, _ = mac.Write(clientNonce)
	_, _ = mac.Write(serverNonce)
	key = mac.Sum(nil)
	return
}

// FinishedProof proves possession of a derived session key.
func FinishedProof(key []byte) (proof []byte, err error) {
	if len(key) != SessionKeySize {
		err = fmt.Errorf("invalid session key length")
		return
	}

	var mac hash.Hash = hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("vpnodns client finished"))
	proof = mac.Sum(nil)
	return
}

// VerifyFinishedProof checks a client finished proof in constant time.
func VerifyFinishedProof(key, proof []byte) (valid bool) {
	var expected []byte
	var err error
	if expected, err = FinishedProof(key); err != nil {
		return
	}

	valid = hmac.Equal(expected, proof)
	return
}

// SealMessage encrypts and authenticates a message payload and its routing metadata.
func SealMessage(key []byte, message Message) (sealed Message, err error) {
	var aead cipher.AEAD
	if aead, err = newSessionAEAD(epochKey(key, message.Sequence)); err != nil {
		return
	}

	var nonce []byte = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		err = fmt.Errorf("generate payload nonce: %w", err)
		return
	}

	sealed = message
	sealed.Payload = aead.Seal(nonce, nonce, message.Payload, messageMetadata(message))
	return
}

// OpenMessage verifies and decrypts a protected message payload.
func OpenMessage(key []byte, message Message) (opened Message, err error) {
	var aead cipher.AEAD
	if aead, err = newSessionAEAD(epochKey(key, message.Sequence)); err != nil {
		return
	}

	if len(message.Payload) < aead.NonceSize()+aead.Overhead() {
		err = fmt.Errorf("encrypted payload too short")
		return
	}

	opened = message
	if opened.Payload, err = aead.Open(nil, message.Payload[:aead.NonceSize()], message.Payload[aead.NonceSize():], messageMetadata(message)); err != nil {
		err = fmt.Errorf("authenticate payload: %w", err)
	}

	return
}

func epochKey(key []byte, sequence uint32) (derived []byte) {
	if len(key) != SessionKeySize {
		return key
	}

	var (
		mac   hash.Hash = hmac.New(sha256.New, key)
		epoch [4]byte
	)

	binary.BigEndian.PutUint32(epoch[:], sequence/KeyRotationSpan)
	_, _ = mac.Write([]byte("vpnodns key epoch\x00"))
	_, _ = mac.Write(epoch[:])
	derived = mac.Sum(nil)
	return
}

func newSessionAEAD(key []byte) (aead cipher.AEAD, err error) {
	if len(key) != SessionKeySize {
		err = fmt.Errorf("invalid session key length")
		return
	}

	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	aead, err = cipher.NewGCM(block)
	return
}

func messageMetadata(message Message) (metadata []byte) {
	metadata = make([]byte, 9)
	metadata[0] = byte(message.Type)
	binary.BigEndian.PutUint32(metadata[1:], message.SessionID)
	binary.BigEndian.PutUint32(metadata[5:], message.Sequence)
	return
}
