package shared

import (
	"fmt"
	"sync"
)

const maxParts = MaxPayloadSize

type (
	// assemblyKey uniquely identifies a fragmented message being reassembled.
	assemblyKey struct {
		sessionID uint32
		sequence  uint32
	}

	// assembly holds the state of a message being reassembled from fragments.
	assembly struct {
		total   uint16
		msgType MessageType
		parts   map[uint16][]byte
		size    int
	}

	// Reassembler rebuilds messages that were split across multiple DNS queries.
	Reassembler struct {
		mu      sync.Mutex
		pending map[assemblyKey]*assembly
	}
)

// NewReassembler creates a new Reassembler instance.
func NewReassembler() (r *Reassembler) {
	r = &Reassembler{
		pending: make(map[assemblyKey]*assembly),
	}

	return r
}

// Add ingests a message fragment. When the full set of parts is available, it returns
// the reassembled message with done=true.
func (r *Reassembler) Add(msg Message) (assembled Message, done bool, err error) {
	if msg.TotalParts == 0 {
		msg.TotalParts = 1
	}

	if msg.TotalParts == 1 {
		assembled = msg
		done = true
		return
	}

	if msg.Part >= msg.TotalParts {
		err = ErrInvalidMessage
		return
	}

	var key assemblyKey = assemblyKey{sessionID: msg.SessionID, sequence: msg.Sequence}

	r.mu.Lock()
	defer r.mu.Unlock()

	var (
		state *assembly
		ok    bool
	)

	if state, ok = r.pending[key]; !ok {
		state = &assembly{
			total:   msg.TotalParts,
			msgType: msg.Type,
			parts:   make(map[uint16][]byte),
		}

		r.pending[key] = state
	} else if state.total != msg.TotalParts || state.msgType != msg.Type {
		delete(r.pending, key)
		err = fmt.Errorf("fragment mismatch for session=%d seq=%d", msg.SessionID, msg.Sequence)
		return
	}

	if _, ok = state.parts[msg.Part]; !ok {
		state.parts[msg.Part] = append([]byte(nil), msg.Payload...)
		state.size += len(msg.Payload)
	}

	if len(state.parts) < int(state.total) {
		return
	}

	var payload, part []byte = make([]byte, 0, state.size), nil
	for i := range state.total {
		if part, ok = state.parts[uint16(i)]; !ok {
			delete(r.pending, key)
			err = ErrIncompletePayload
			return
		}

		payload = append(payload, part...)
	}

	delete(r.pending, key)
	assembled = Message{
		Type:       msg.Type,
		SessionID:  msg.SessionID,
		Sequence:   msg.Sequence,
		TotalParts: msg.TotalParts,
		Part:       0,
		Payload:    payload,
	}

	done = true
	return
}

// MaxQueryPayload returns the largest payload length that can fit into a single DNS query name for the given domain.
func MaxQueryPayload(domain string) (max int) {
	max = maxQueryPayload(domain)
	return
}

// SplitMessageForQuery divides a message into fragments that each fit within DNS name limits.
func SplitMessageForQuery(msg Message, domain string) (fragments []Message, err error) {
	var maxChunk, partCount, offset int = maxQueryPayload(domain), 0, 0

	if maxChunk <= 0 {
		err = fmt.Errorf("domain %q leaves no room for payload", domain)
		return
	}

	if len(msg.Payload) <= maxChunk {
		msg.TotalParts = 1
		msg.Part = 0
		fragments = []Message{msg}
		return
	}

	if partCount = (len(msg.Payload) + maxChunk - 1) / maxChunk; partCount > maxParts {
		err = fmt.Errorf("message requires too many parts: %d", partCount)
		return
	}

	fragments = make([]Message, 0, partCount)
	for offset = 0; offset < len(msg.Payload); offset += maxChunk {
		var part Message = msg
		// #nosec G115 -- partCount is bounded by maxParts (MaxUint16) above.
		part.TotalParts = uint16(partCount)
		// #nosec G115 -- len(fragments) is always less than the bounded partCount.
		part.Part = uint16(len(fragments))
		part.Payload = append([]byte(nil), msg.Payload[offset:min(offset+maxChunk, len(msg.Payload))]...)
		fragments = append(fragments, part)
	}

	return
}

func maxQueryPayload(domain string) (max int) {
	domain = normalizeDomain(domain)
	var err error
	if _, _, err = domainLabelInfo(domain); err != nil {
		return
	}

	var low, high, mid int = 0, MaxPayloadSize, 0

	for low < high {
		mid = (low + high + 1) / 2
		if encodedWireLength(mid, domain) <= MaxDNSWireLength {
			low = mid
		} else {
			high = mid - 1
		}
	}

	max = low
	return
}

func encodedWireLength(payloadLen int, domain string) (wireLen int) {
	var wireBytes, encodedLen, payloadLabels, domainLabels, domainLen int

	wireBytes = messageHeaderSize + payloadLen
	encodedLen = b32Encoder.EncodedLen(wireBytes)
	payloadLabels = (encodedLen + maxLabelLength - 1) / maxLabelLength

	domain = normalizeDomain(domain)
	domainLabels, domainLen, _ = domainLabelInfo(domain)

	var labelCount int = payloadLabels + domainLabels
	wireLen = encodedLen + domainLen + labelCount + 1 // +1 for root
	return
}
