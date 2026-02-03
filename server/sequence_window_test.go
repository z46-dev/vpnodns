package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSequenceWindow(t *testing.T) {
	var w sequenceWindow

	assert.True(t, w.Accept(10))
	assert.True(t, w.Accept(12))
	assert.True(t, w.Accept(11))
	assert.False(t, w.Accept(11)) // duplicate
	assert.False(t, w.Accept(10)) // duplicate in-window

	assert.True(t, w.Accept(200))
	assert.False(t, w.Accept(10)) // too old
}
