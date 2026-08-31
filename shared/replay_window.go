package shared

import "sync"

const ReplayWindowSize = 64

// ReplayWindow accepts unseen sequence numbers within a bounded sliding window.
type ReplayWindow struct {
	mu          sync.Mutex
	highest     uint32
	seen        uint64
	initialized bool
}

// Accept records a sequence number and rejects duplicates or values outside the window.
func (w *ReplayWindow) Accept(sequence uint32) (accepted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initialized {
		w.highest = sequence
		w.seen = 1
		w.initialized = true
		accepted = true
		return
	}

	if sequence > w.highest {
		var shift uint32 = sequence - w.highest
		if shift >= ReplayWindowSize {
			w.seen = 0
		} else {
			w.seen <<= shift
		}

		w.highest = sequence
		w.seen |= 1
		accepted = true
		return
	}

	var distance uint32 = w.highest - sequence
	if distance >= ReplayWindowSize || w.seen&(uint64(1)<<distance) != 0 {
		return
	}

	w.seen |= uint64(1) << distance
	accepted = true
	return
}
