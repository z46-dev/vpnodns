package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/z46-dev/vpnodns/shared"
)

func TestAuthSessions(t *testing.T) {
	var (
		sessions   *authSessions = newAuthSessions()
		key        []byte        = make([]byte, shared.SessionKeySize)
		authorized bool
	)

	_, authorized = sessions.key(42)
	assert.False(t, authorized)

	sessions.addPending(42, key)
	_, authorized = sessions.key(42)
	assert.False(t, authorized)

	var proof []byte
	proof, _ = shared.FinishedProof(key)
	assert.True(t, sessions.activate(42, proof))

	_, authorized = sessions.key(42)
	assert.True(t, authorized)
}

func TestAuthSessionReplayAndExpiry(t *testing.T) {
	var (
		now      time.Time     = time.Unix(1000, 0)
		sessions *authSessions = newAuthSessionsWithClock(func() time.Time { return now })
		key      []byte        = make([]byte, shared.SessionKeySize)
		proof    []byte
	)

	sessions.addPending(7, key)
	proof, _ = shared.FinishedProof(key)
	assert.True(t, sessions.activate(7, proof))

	var (
		message shared.Message = shared.Message{Type: shared.MessageTypeClientPoll, SessionID: 7, Sequence: 10}
		sealed  shared.Message
		err     error
	)

	sealed, err = shared.SealMessage(key, message)
	assert.NoError(t, err)

	_, err = sessions.open(sealed)
	assert.NoError(t, err)

	_, err = sessions.open(sealed)
	assert.ErrorContains(t, err, "replayed")

	now = now.Add(sessionIdleTTL + time.Second)
	message.Sequence++
	sealed, err = shared.SealMessage(key, message)
	assert.NoError(t, err)

	_, err = sessions.open(sealed)
	assert.ErrorContains(t, err, "expired")
}

func TestPendingAndAbsoluteSessionExpiry(t *testing.T) {
	var (
		now      time.Time     = time.Unix(2000, 0)
		sessions *authSessions = newAuthSessionsWithClock(func() time.Time { return now })
		key      []byte        = make([]byte, shared.SessionKeySize)
	)

	sessions.addPending(1, key)
	now = now.Add(pendingSessionTTL + time.Second)

	var proof []byte
	proof, _ = shared.FinishedProof(key)
	assert.False(t, sessions.activate(1, proof))

	sessions.addPending(2, key)
	assert.True(t, sessions.activate(2, proof))
	now = now.Add(sessionMaxTTL + time.Second)

	var authorized bool
	_, authorized = sessions.key(2)
	assert.False(t, authorized)
}
