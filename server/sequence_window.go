package main

type sequenceWindow struct {
	max         uint32
	seenMask    uint64
	initialized bool
}

func (w *sequenceWindow) Accept(seq uint32) (ok bool) {
	if !w.initialized {
		w.max = seq
		w.seenMask = 1
		w.initialized = true
		return true
	}

	if seq > w.max {
		var shift uint32 = seq - w.max
		if shift >= 64 {
			w.seenMask = 1
		} else {
			w.seenMask = (w.seenMask << shift) | 1
		}
		w.max = seq
		return true
	}

	var behind uint32 = w.max - seq
	if behind >= 64 {
		return false
	}

	var bit uint64 = uint64(1) << behind
	if w.seenMask&bit != 0 {
		return false
	}

	w.seenMask |= bit
	return true
}
