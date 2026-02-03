package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/z46-dev/vpnodns/shared"
)

type sessionState struct {
	queue       chan []byte
	lastSeen    time.Time
	clientIP    string
	established bool
	sessionKey  []byte
	clientSeq   sequenceWindow
}

type sessionManager struct {
	mu         sync.Mutex
	sessions   map[uint32]*sessionState
	byClientIP map[string]uint32
	queueSize  int
	ttl        time.Duration
}

func newSessionManager(queueSize int, ttl time.Duration) *sessionManager {
	if queueSize <= 0 {
		queueSize = 64
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}

	return &sessionManager{
		sessions:   make(map[uint32]*sessionState),
		byClientIP: make(map[string]uint32),
		queueSize:  queueSize,
		ttl:        ttl,
	}
}

func (m *sessionManager) StartJanitor(ctx context.Context) {
	var tick *time.Ticker = time.NewTicker(15 * time.Second)
	go func() {
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				m.pruneExpired(time.Now())
			}
		}
	}()
}

func (m *sessionManager) Register(sessionID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var old *sessionState
	var ok bool
	if old, ok = m.sessions[sessionID]; ok && old.clientIP != "" {
		delete(m.byClientIP, old.clientIP)
	}

	m.sessions[sessionID] = &sessionState{
		queue:    make(chan []byte, m.queueSize),
		lastSeen: time.Now(),
	}
}

func (m *sessionManager) Touch(sessionID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertLocked(sessionID).lastSeen = time.Now()
}

func (m *sessionManager) MarkEstablished(sessionID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var state *sessionState = m.upsertLocked(sessionID)
	state.established = true
	state.lastSeen = time.Now()
}

func (m *sessionManager) IsEstablished(sessionID uint32) (ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var state *sessionState
	state, ok = m.sessions[sessionID]
	if !ok {
		return false
	}
	return state.established
}

func (m *sessionManager) SetSessionKey(sessionID uint32, key []byte) {
	if len(key) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var state *sessionState = m.upsertLocked(sessionID)
	state.sessionKey = append([]byte(nil), key...)
	state.lastSeen = time.Now()
}

func (m *sessionManager) SessionKey(sessionID uint32) (key []byte, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var state *sessionState
	state, ok = m.sessions[sessionID]
	if !ok || len(state.sessionKey) == 0 {
		return nil, false
	}
	state.lastSeen = time.Now()
	return append([]byte(nil), state.sessionKey...), true
}

func (m *sessionManager) AcceptClientSequence(sessionID, seq uint32) (accepted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var state *sessionState
	var ok bool
	if state, ok = m.sessions[sessionID]; !ok {
		return false
	}

	state.lastSeen = time.Now()
	return state.clientSeq.Accept(seq)
}

func (m *sessionManager) BindClientIP(sessionID uint32, ip net.IP) {
	if ip == nil {
		return
	}

	var key string = ip.String()
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.upsertLocked(sessionID)
	if state.clientIP != "" && state.clientIP != key {
		delete(m.byClientIP, state.clientIP)
	}

	if prevSession, ok := m.byClientIP[key]; ok && prevSession != sessionID {
		if prevState, ok := m.sessions[prevSession]; ok {
			prevState.clientIP = ""
		}
	}

	state.clientIP = key
	state.lastSeen = time.Now()
	m.byClientIP[key] = sessionID
}

func (m *sessionManager) Dequeue(sessionID uint32) (pkt []byte, ok bool) {
	m.mu.Lock()
	state, found := m.sessions[sessionID]
	if found {
		state.lastSeen = time.Now()
	}
	m.mu.Unlock()

	if !found {
		return nil, false
	}

	select {
	case pkt = <-state.queue:
		return pkt, true
	default:
		return nil, false
	}
}

func (m *sessionManager) EnqueueByPacket(pkt []byte) (queued bool) {
	_, dst, ok := shared.PacketSrcDst(pkt)
	if ok {
		return m.EnqueueForIP(dst, pkt)
	}
	return m.enqueueFallback(pkt)
}

func (m *sessionManager) EnqueueForIP(dst net.IP, pkt []byte) (queued bool) {
	if dst == nil {
		return m.enqueueFallback(pkt)
	}

	var target uint32
	m.mu.Lock()
	target, queued = m.byClientIP[dst.String()]
	m.mu.Unlock()
	if !queued {
		return m.enqueueFallback(pkt)
	}
	return m.enqueueForSession(target, pkt)
}

func (m *sessionManager) enqueueFallback(pkt []byte) (queued bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions) == 1 {
		for sessionID := range m.sessions {
			return m.enqueueForSessionLocked(sessionID, pkt)
		}
	}

	return false
}

func (m *sessionManager) enqueueForSession(sessionID uint32, pkt []byte) (queued bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enqueueForSessionLocked(sessionID, pkt)
}

func (m *sessionManager) enqueueForSessionLocked(sessionID uint32, pkt []byte) (queued bool) {
	state, ok := m.sessions[sessionID]
	if !ok {
		return false
	}

	cloned := append([]byte(nil), pkt...)
	select {
	case state.queue <- cloned:
		state.lastSeen = time.Now()
		return true
	default:
		select {
		case <-state.queue:
		default:
		}
		select {
		case state.queue <- cloned:
			state.lastSeen = time.Now()
			return true
		default:
			return false
		}
	}
}

func (m *sessionManager) upsertLocked(sessionID uint32) *sessionState {
	state, ok := m.sessions[sessionID]
	if ok {
		return state
	}

	state = &sessionState{
		queue:    make(chan []byte, m.queueSize),
		lastSeen: time.Now(),
	}
	m.sessions[sessionID] = state
	return state
}

func (m *sessionManager) pruneExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for sessionID, state := range m.sessions {
		if now.Sub(state.lastSeen) < m.ttl {
			continue
		}

		if state.clientIP != "" {
			delete(m.byClientIP, state.clientIP)
		}

		delete(m.sessions, sessionID)
	}
}
