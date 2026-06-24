package openid4vci

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
)

// session holds the state of one issuance flow, from /authorize through
// /credential. It is created at /authorize and looked up by authorization code
// at /token and by access token at /credential.
type session struct {
	id            string
	redirectURI   string
	state         string
	codeChallenge string
	configID      string
	// recipientHost and recipientDetail describe the wallet the credential will be
	// issued to, derived from the OAuth client_id and shown on the consent screen.
	// recipientHost is the prominent host; recipientDetail is the muted path/GUID.
	recipientHost   string
	recipientDetail string

	// attrs is set once authentication finishes.
	attrs *auth.Attributes
	// services are the credential services chosen on the consent screen.
	services []string

	code        string
	accessToken string
	createdAt   time.Time
}

// sessionStore is an in-memory, TTL-bounded store for flow sessions and the
// c_nonces handed out for credential-request proofs.
type sessionStore struct {
	mu      sync.Mutex
	byID    map[string]*session
	byCode  map[string]*session
	byToken map[string]*session
	nonces  map[string]time.Time
	ttl     time.Duration
	now     func() time.Time
}

func newSessionStore(ttl time.Duration, now func() time.Time) *sessionStore {
	if now == nil {
		now = time.Now
	}
	return &sessionStore{
		byID:    map[string]*session{},
		byCode:  map[string]*session{},
		byToken: map[string]*session{},
		nonces:  map[string]time.Time{},
		ttl:     ttl,
		now:     now,
	}
}

func (s *sessionStore) create(sess *session) {
	sess.id = newID()
	sess.createdAt = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[sess.id] = sess
}

func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// bindCode attaches a freshly minted authorization code to the session.
func (s *sessionStore) bindCode(sess *session) string {
	code := newID()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.code = code
	s.byCode[code] = sess
	return code
}

// takeByCode returns and removes the session for an authorization code, so a
// code can be redeemed only once.
func (s *sessionStore) takeByCode(code string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byCode[code]
	delete(s.byCode, code)
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// bindToken attaches a freshly minted access token to the session.
func (s *sessionStore) bindToken(sess *session) string {
	token := newID()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.accessToken = token
	s.byToken[token] = sess
	return token
}

func (s *sessionStore) getByToken(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byToken[token]
	if !ok || s.expired(sess) {
		return nil, false
	}
	return sess, true
}

// issueNonce mints a c_nonce and records it as valid for the store's TTL.
func (s *sessionStore) issueNonce() string {
	nonce := newID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = s.now()
	return nonce
}

// consumeNonce reports whether the nonce is valid, removing it so it cannot be
// replayed.
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

func (s *sessionStore) expired(sess *session) bool {
	return s.now().Sub(sess.createdAt) > s.ttl
}

// gc evicts expired sessions and nonces until the store is stopped.
func (s *sessionStore) gc(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
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
			delete(s.byCode, sess.code)
			delete(s.byToken, sess.accessToken)
		}
	}
	for nonce, issued := range s.nonces {
		if now.Sub(issued) > s.ttl {
			delete(s.nonces, nonce)
		}
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
