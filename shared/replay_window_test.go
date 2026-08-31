package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplayWindow(t *testing.T) {
	var window ReplayWindow
	assert.True(t, window.Accept(100))
	assert.False(t, window.Accept(100))
	assert.True(t, window.Accept(102))
	assert.True(t, window.Accept(101))
	assert.False(t, window.Accept(101))
	assert.True(t, window.Accept(200))
	assert.False(t, window.Accept(100))
}
