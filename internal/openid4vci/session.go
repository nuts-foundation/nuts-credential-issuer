package openid4vci

import (
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/id"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// session is the OAuth/OpenID4VCI protocol session correlating the multiple HTTP
// requests of one authorization-code flow. It wraps the business issuance with
// the protocol artifacts (redirect_uri, state, PKCE challenge, code, token).
type session struct {
	issuance      *issuance.Issuance
	redirectURI   string
	state         string
	codeChallenge string
	code          string
	token         string
	createdAt     time.Time
}

func (s *session) id() string { return s.issuance.ID() }

// sessionStore is the in-memory store of in-flight protocol sessions and the
// c_nonces handed out for credential-request proofs, bounded by a TTL.
type sessionStore struct {
	mu      sync.Mutex
	byID    map[string]*session
	byCode  map[string]string // code -> id
	byToken map[string]string // token -> id
	nonces  map[string]time.Time
	ttl     time.Duration
	now     func() time.Time
	stop    chan struct{}
}

func newSessionStore(ttl time.Duration, now func() time.Time) *sessionStore {
	if now == nil {
		now = time.Now
	}
	s := &sessionStore{
		byID:    map[string]*session{},
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

// create stamps and stores a new session, keyed by its id.
func (s *sessionStore) create(sess *session) {
	sess.createdAt = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[sess.id()] = sess
}

// get returns the live (non-expired) session for an id.
func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// bindCode indexes a session by its issued authorization code.
func (s *sessionStore) bindCode(code, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byCode[code] = id
}

// takeByCode returns and removes the session for a code (codes are single-use).
func (s *sessionStore) takeByCode(code string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byCode[code]
	delete(s.byCode, code)
	if !ok {
		return nil, false
	}
	sess, ok := s.byID[id]
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// bindToken indexes a session by its issued access token.
func (s *sessionStore) bindToken(token, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken[token] = id
}

// getByToken returns the live (non-expired) session for an access token.
func (s *sessionStore) getByToken(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byToken[token]
	if !ok {
		return nil, false
	}
	sess, ok := s.byID[id]
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// issueNonce mints a c_nonce valid for the store's TTL.
func (s *sessionStore) issueNonce() string {
	nonce := id.New()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = s.now()
	return nonce
}

// consumeNonce reports whether the nonce is valid, removing it (single-use).
func (s *sessionStore) consumeNonce(nonce string) bool {
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

func (s *sessionStore) close() { close(s.stop) }

func (s *sessionStore) expired(sess *session) bool {
	return s.now().Sub(sess.createdAt) > s.ttl
}

func (s *sessionStore) gc() {
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

func (s *sessionStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.byID {
		if now.Sub(sess.createdAt) > s.ttl {
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
