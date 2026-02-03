package main

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionManagerRouteByClientIP(t *testing.T) {
	mgr := newSessionManager(2, time.Minute)
	mgr.Register(100)
	mgr.BindClientIP(100, net.ParseIP("10.44.0.2"))

	ok := mgr.EnqueueForIP(net.ParseIP("10.44.0.2"), []byte("pkt"))
	assert.True(t, ok)

	pkt, ok := mgr.Dequeue(100)
	assert.True(t, ok)
	assert.Equal(t, []byte("pkt"), pkt)
}

func TestSessionManagerFallbackSingleSession(t *testing.T) {
	mgr := newSessionManager(2, time.Minute)
	mgr.Register(123)

	ok := mgr.EnqueueByPacket([]byte("not-an-ip-packet"))
	assert.True(t, ok)

	pkt, ok := mgr.Dequeue(123)
	assert.True(t, ok)
	assert.Equal(t, []byte("not-an-ip-packet"), pkt)
}

func TestSessionManagerPrunesExpired(t *testing.T) {
	mgr := newSessionManager(2, 5*time.Millisecond)
	mgr.Register(1)
	mgr.BindClientIP(1, net.ParseIP("10.44.0.2"))

	time.Sleep(10 * time.Millisecond)
	mgr.pruneExpired(time.Now())

	ok := mgr.EnqueueForIP(net.ParseIP("10.44.0.2"), []byte("pkt"))
	assert.False(t, ok)
}

func TestSessionManagerSequenceWindow(t *testing.T) {
	mgr := newSessionManager(2, time.Minute)
	mgr.Register(50)

	assert.True(t, mgr.AcceptClientSequence(50, 10))
	assert.True(t, mgr.AcceptClientSequence(50, 12))
	assert.True(t, mgr.AcceptClientSequence(50, 11))
	assert.False(t, mgr.AcceptClientSequence(50, 11))
}
