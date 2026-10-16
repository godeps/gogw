package gogw

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"time"
)

// sessionBinding is one authenticated unit's binding to a release and a build.
type sessionBinding struct {
	view     *view
	build    string
	lastSeen time.Time
}

// sessionStore keeps per-unit routing stable without storing the unit itself:
// entries are keyed by a keyed hash of the authenticated principal, so the store
// holds no identity that could leak through diagnostics or a memory dump.
type sessionStore struct {
	secret []byte
	compat time.Duration
	limit  int

	mu      sync.Mutex
	entries map[[32]byte]*sessionBinding
}

func newSessionStore(secret []byte, compat time.Duration, limit int) *sessionStore {
	return &sessionStore{secret: secret, compat: compat, limit: limit, entries: map[[32]byte]*sessionBinding{}}
}

// key derives the store key of one principal. The service and tenant are part of
// the input so the same subject in two services never shares a binding.
func (s *sessionStore) key(service, tenant, subject string) [32]byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(service))
	mac.Write([]byte{0})
	mac.Write([]byte(tenant))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return key
}

// lookup returns the binding of one unit, if any.
func (s *sessionStore) lookup(key [32]byte) (*sessionBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.entries[key]
	return binding, ok
}

// bind pins one unit to a view and build, reporting whether this is the first
// time the unit is exposed to that release.
func (s *sessionStore) bind(key [32]byte, target *view, build string, now time.Time) (*sessionBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if binding, ok := s.entries[key]; ok {
		exposed := binding.view != target || binding.build != build
		if binding.view != target {
			binding.view.release()
			target.acquire()
			binding.view = target
		}
		binding.build, binding.lastSeen = build, now
		return binding, exposed
	}
	target.acquire()
	binding := &sessionBinding{view: target, build: build, lastSeen: now}
	s.entries[key] = binding
	s.evictLocked(now)
	return binding, true
}

// touch refreshes the activity time of one binding.
func (s *sessionStore) touch(binding *sessionBinding, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding.lastSeen = now
}

// forget drops one binding whose view no longer admits the build it was pinned
// to, so the next request re-evaluates the release instead of reusing a
// decision the release has already invalidated.
func (s *sessionStore) forget(key [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.entries[key]
	if !ok {
		return
	}
	binding.view.release()
	delete(s.entries, key)
}

// rebind moves every binding pinned to one view onto its replacement. A
// membership change re-compiles the same release, so the units stay exposed to
// the same build and must not keep routing through the superseded view.
func (s *sessionStore) rebind(from, to *view) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	moved := 0
	for _, binding := range s.entries {
		if binding.view != from {
			continue
		}
		binding.view.release()
		to.acquire()
		binding.view = to
		moved++
	}
	return moved
}

// evictLocked drops the oldest bindings once the store is full. Eviction releases
// the pinned view, which is what eventually reclaims a retired release.
func (s *sessionStore) evictLocked(now time.Time) {
	if len(s.entries) <= s.limit {
		return
	}
	s.sweepLocked(now, len(s.entries)-s.limit)
}

// sweep releases bindings whose compatibility window elapsed and, when over
// capacity, the least recently used ones.
func (s *sessionStore) sweep(now time.Time, over int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now, over)
}

func (s *sessionStore) sweepLocked(now time.Time, over int) int {
	released := 0
	for key, binding := range s.entries {
		if now.Sub(binding.lastSeen) > s.compat {
			binding.view.release()
			delete(s.entries, key)
			released++
		}
	}
	for released < over && len(s.entries) > 0 {
		var oldestKey [32]byte
		var oldest *sessionBinding
		for key, binding := range s.entries {
			if oldest == nil || binding.lastSeen.Before(oldest.lastSeen) {
				oldestKey, oldest = key, binding
			}
		}
		oldest.view.release()
		delete(s.entries, oldestKey)
		released++
	}
	return released
}

func (s *sessionStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// withinWindow reports whether a pinned view may still serve one unit after it
// stopped being active.
func withinWindow(pinned *view, compat time.Duration, now time.Time) bool {
	retiredAt := pinned.retirement()
	if retiredAt.IsZero() {
		return true
	}
	return now.Before(retiredAt.Add(compat))
}
