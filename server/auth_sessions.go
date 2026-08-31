package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/z46-dev/vpnodns/shared"
)

type (
	// authSessions tracks session IDs that completed credential verification.
	authSessions struct {
		mu       sync.RWMutex
		sessions map[uint32]authSession
		now      func() time.Time
	}

	authSession struct {
		key          []byte
		active       bool
		createdAt    time.Time
		lastActivity time.Time
		replay       *shared.ReplayWindow
	}
)

const (
	pendingSessionTTL = time.Minute
	sessionIdleTTL    = 5 * time.Minute
	sessionMaxTTL     = 24 * time.Hour
)

// newAuthSessions creates an empty authenticated-session registry.
func newAuthSessions() (sessions *authSessions) {
	sessions = newAuthSessionsWithClock(time.Now)
	return
}

func newAuthSessionsWithClock(now func() time.Time) (sessions *authSessions) {
	sessions = &authSessions{sessions: make(map[uint32]authSession), now: now}
	return
}

// addPending stores key material until the client proves possession.
func (s *authSessions) addPending(sessionID uint32, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var now time.Time = s.now()
	s.sessions[sessionID] = authSession{
		key:          append([]byte(nil), key...),
		createdAt:    now,
		lastActivity: now,
		replay:       new(shared.ReplayWindow),
	}
}

// activate verifies the finished proof and activates a pending session.
func (s *authSessions) activate(sessionID uint32, proof []byte) (active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		session authSession
		ok      bool
	)

	if session, ok = s.sessions[sessionID]; !ok || s.expired(session, s.now()) || !shared.VerifyFinishedProof(session.key, proof) {
		delete(s.sessions, sessionID)
		return
	}

	session.active = true
	session.lastActivity = s.now()
	s.sessions[sessionID] = session
	active = true
	return
}

// key returns a copy of an active session key.
func (s *authSessions) key(sessionID uint32) (key []byte, authorized bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var session authSession
	if session, authorized = s.sessions[sessionID]; !authorized {
		return
	}

	if s.expired(session, s.now()) {
		delete(s.sessions, sessionID)
		authorized = false
		return
	}

	if session.active {
		key = append([]byte(nil), session.key...)
		session.lastActivity = s.now()
		s.sessions[sessionID] = session
	} else {
		authorized = false
	}

	return
}

// open authenticates an inbound message, enforces expiry, and rejects replayed sequences.
func (s *authSessions) open(message shared.Message) (opened shared.Message, err error) {
	var (
		key    []byte
		replay *shared.ReplayWindow
	)

	s.mu.Lock()

	var (
		session authSession
		ok      bool
	)

	if session, ok = s.sessions[message.SessionID]; !ok || !session.active || s.expired(session, s.now()) {
		delete(s.sessions, message.SessionID)
		s.mu.Unlock()
		err = fmt.Errorf("unauthenticated or expired session %d", message.SessionID)
		return
	}

	key = append([]byte(nil), session.key...)
	replay = session.replay
	s.mu.Unlock()

	if opened, err = shared.OpenMessage(key, message); err != nil {
		return
	}

	if !replay.Accept(message.Sequence) {
		err = fmt.Errorf("replayed or stale sequence %d", message.Sequence)
		return
	}

	s.mu.Lock()
	if session, ok = s.sessions[message.SessionID]; ok {
		session.lastActivity = s.now()
		s.sessions[message.SessionID] = session
	}

	s.mu.Unlock()
	return
}

func (s *authSessions) expired(session authSession, now time.Time) (expired bool) {
	if !session.active {
		expired = now.Sub(session.createdAt) > pendingSessionTTL
		return
	}

	expired = now.Sub(session.lastActivity) > sessionIdleTTL || now.Sub(session.createdAt) > sessionMaxTTL
	return
}
