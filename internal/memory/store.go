// Package memory is an in-memory implementation of the issuance store and the
// c_nonce set, bounded by a TTL. It indexes issuances by id, authorization code
// and access token. Per-issuance field safety lives in the issuance aggregate;
// this store only guards its own index maps.
package memory

import (
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// Store keeps issuances and issued c_nonces in memory.
type Store struct {
	mu      sync.Mutex
	byID    map[string]*issuance.Issuance
	byCode  map[string]string // code -> id
	byToken map[string]string // token -> id
	nonces  map[string]time.Time
	ttl     time.Duration
	now     func() time.Time
	stop    chan struct{}
}

// NewStore returns a store and starts its background reaper. Call Close to stop it.
func NewStore(ttl time.Duration, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	s := &Store{
		byID:    map[string]*issuance.Issuance{},
		byCode:  map[string]string{},
		byToken: map[string]string{},
		nonces:  map[string]time.Time{},
		ttl:     ttl,
		now:     now,
		stop:    make(chan struct{}),
	}
	go s.gc()
	return s
}

// Create stores a new issuance.
func (s *Store) Create(iss *issuance.Issuance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[iss.ID()] = iss
}

// Get returns the issuance for an id.
func (s *Store) Get(id string) (*issuance.Issuance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	iss, ok := s.byID[id]
	if !ok || s.expired(iss) {
		return nil, false
	}
	return iss, true
}

// BindCode indexes an authorization code to an issuance id.
func (s *Store) BindCode(code, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byCode[code] = id
}

// TakeByCode returns and removes the issuance for an authorization code, so a
// code can be redeemed only once.
func (s *Store) TakeByCode(code string) (*issuance.Issuance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byCode[code]
	delete(s.byCode, code)
	if !ok {
		return nil, false
	}
	iss, ok := s.byID[id]
	if !ok || s.expired(iss) {
		return nil, false
	}
	return iss, true
}

// BindToken indexes an access token to an issuance id.
func (s *Store) BindToken(token, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken[token] = id
}

// ByToken returns the issuance for an access token.
func (s *Store) ByToken(token string) (*issuance.Issuance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byToken[token]
	if !ok {
		return nil, false
	}
	iss, ok := s.byID[id]
	if !ok || s.expired(iss) {
		return nil, false
	}
	return iss, true
}

// PutNonce records a c_nonce as valid for the store's TTL.
func (s *Store) PutNonce(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = s.now()
}

// ConsumeNonce reports whether the nonce is valid, removing it so it cannot be
// replayed.
func (s *Store) ConsumeNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	issued, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return s.now().Sub(issued) <= s.ttl
}

// Close stops the background reaper.
func (s *Store) Close() { close(s.stop) }

func (s *Store) expired(iss *issuance.Issuance) bool {
	return s.now().Sub(iss.CreatedAt()) > s.ttl
}

func (s *Store) gc() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *Store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, iss := range s.byID {
		if now.Sub(iss.CreatedAt()) > s.ttl {
			delete(s.byID, id)
		}
	}
	for code, id := range s.byCode {
		if _, ok := s.byID[id]; !ok {
			delete(s.byCode, code)
		}
	}
	for token, id := range s.byToken {
		if _, ok := s.byID[id]; !ok {
			delete(s.byToken, token)
		}
	}
	for nonce, issued := range s.nonces {
		if now.Sub(issued) > s.ttl {
			delete(s.nonces, nonce)
		}
	}
}
