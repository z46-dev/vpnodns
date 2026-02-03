package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	TrafficClientToServer byte = 1
	TrafficServerToClient byte = 2
)

func EncryptMessagePayload(msg Message, key []byte, direction byte) (encrypted Message, err error) {
	encrypted = msg
	if len(msg.Payload) == 0 {
		return
	}

	var aead cipher.AEAD
	if aead, err = newAEAD(key); err != nil {
		return
	}

	var nonce []byte = derivePayloadNonce(msg, direction)
	encrypted.Payload = aead.Seal(nil, nonce, msg.Payload, messageAAD(msg))
	return
}

func DecryptMessagePayload(msg Message, key []byte, direction byte) (decrypted Message, err error) {
	decrypted = msg
	if len(msg.Payload) == 0 {
		return
	}

	var aead cipher.AEAD
	if aead, err = newAEAD(key); err != nil {
		return
	}

	var nonce []byte = derivePayloadNonce(msg, direction)
	if decrypted.Payload, err = aead.Open(nil, nonce, msg.Payload, messageAAD(msg)); err != nil {
		err = fmt.Errorf("decrypt payload: %w", err)
		return
	}
	return
}

func newAEAD(key []byte) (aead cipher.AEAD, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		err = fmt.Errorf("init cipher: %w", err)
		return
	}

	aead, err = cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("init gcm: %w", err)
		return
	}
	return
}

func derivePayloadNonce(msg Message, direction byte) (nonce []byte) {
	var data [14]byte
	data[0] = direction
	data[1] = byte(msg.Type)
	binary.BigEndian.PutUint32(data[2:], msg.SessionID)
	binary.BigEndian.PutUint32(data[6:], msg.Sequence)
	binary.BigEndian.PutUint16(data[10:], msg.TotalParts)
	binary.BigEndian.PutUint16(data[12:], msg.Part)

	var sum [32]byte = sha256.Sum256(data[:])
	nonce = append([]byte(nil), sum[:12]...)
	return
}

func messageAAD(msg Message) (aad []byte) {
	var data [13]byte
	data[0] = byte(msg.Type)
	binary.BigEndian.PutUint32(data[1:], msg.SessionID)
	binary.BigEndian.PutUint32(data[5:], msg.Sequence)
	binary.BigEndian.PutUint16(data[9:], msg.TotalParts)
	binary.BigEndian.PutUint16(data[11:], msg.Part)
	aad = data[:]
	return
}
