package gogw

import (
	"context"
	"errors"
	"sync"
	"time"
)

// revocationState is the service-scoped revocation state: a monotone epoch and
// the cumulative set of revoked release hashes. It is a union, never a
// replacement, so a control plane that forgets a revocation or replays an older
// document cannot resurrect a revoked release.
type revocationState struct {
	mu      sync.RWMutex
	epoch   uint64
	hashes  map[string]bool
	expires time.Time
}

func newRevocationState(epoch uint64, hashes []string) *revocationState {
	state := &revocationState{epoch: epoch, hashes: map[string]bool{}}
	for _, hash := range hashes {
		state.hashes[hash] = true
	}
	return state
}

func (r *revocationState) revoked(hash string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hashes[hash]
}

func (r *revocationState) snapshot() (uint64, []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hashes := make([]string, 0, len(r.hashes))
	for hash := range r.hashes {
		hashes = append(hashes, hash)
	}
	return r.epoch, hashes
}

// merge folds one revocation document into the state and reports the release
// hashes that became revoked, which is what triggers stream cancellation.
func (r *revocationState) merge(epoch uint64, hashes []string, expires time.Time) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if epoch < r.epoch {
		return nil, errors.New("gogw: revocation epoch regression")
	}
	var newly []string
	for _, hash := range hashes {
		if r.hashes[hash] {
			continue
		}
		r.hashes[hash] = true
		newly = append(newly, hash)
	}
	r.epoch = epoch
	if expires.After(r.expires) {
		r.expires = expires
	}
	return newly, nil
}

// streamRegistry tracks in-flight requests so revocation and the drain deadline
// can terminate long-lived responses instead of waiting for them forever.
type streamRegistry struct {
	mu      sync.Mutex
	next    uint64
	streams map[uint64]streamEntry
}

type streamEntry struct {
	view   *view
	cancel context.CancelFunc
}

func newStreamRegistry() *streamRegistry {
	return &streamRegistry{streams: map[uint64]streamEntry{}}
}

// add registers one in-flight request and returns its handle.
func (s *streamRegistry) add(v *view, cancel context.CancelFunc) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.streams[s.next] = streamEntry{view: v, cancel: cancel}
	return s.next
}

func (s *streamRegistry) remove(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams, id)
}

// cancelView terminates every in-flight request served by one view.
func (s *streamRegistry) cancelView(v *view) {
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.streams))
	for _, entry := range s.streams {
		if entry.view == v {
			cancels = append(cancels, entry.cancel)
		}
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// cancelAll terminates every in-flight request, which is how the drain deadline
// is enforced.
func (s *streamRegistry) cancelAll() int {
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.streams))
	for _, entry := range s.streams {
		cancels = append(cancels, entry.cancel)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels)
}

func (s *streamRegistry) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}
