// Package issuance is the domain model for one credential-issuance flow.
//
// An Issuance is an aggregate with an explicit state machine: it moves
// Started -> Authenticated -> Consented -> Tokenized -> Issued, and rejects any
// out-of-order transition. All access is synchronised, so concurrent requests
// touching the same issuance are safe. The domain has no transport, HTTP or node
// dependencies.
package issuance

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Status is the lifecycle state of an Issuance.
type Status int

const (
	Started       Status = iota // authorization started, awaiting authentication
	Authenticated               // user authenticated, awaiting consent
	Consented                   // consent granted, authorization code issued
	Tokenized                   // access token issued, awaiting credential request
	Issued                      // credential issued (terminal)
)

// ErrInvalidState is returned when a transition is attempted from the wrong state.
var ErrInvalidState = errors.New("invalid issuance state for this operation")

// ErrPKCE is returned when the PKCE code_verifier does not match the challenge.
var ErrPKCE = errors.New("PKCE verification failed")

// ErrRedirectURIMismatch is returned when the token redirect_uri differs from
// the one used at authorization.
var ErrRedirectURIMismatch = errors.New("redirect_uri mismatch")

// Organization is the authenticated subject the credential is issued for.
type Organization struct {
	LegalName  string
	Identifier string
}

// Recipient is a human-readable label for the wallet the credential is issued to.
type Recipient struct {
	Host   string
	Detail string
}

// Issuance is the aggregate root of one issuance flow.
type Issuance struct {
	mu sync.Mutex

	id            string
	redirectURI   string
	oauthState    string
	codeChallenge string
	configID      string
	recipient     Recipient
	createdAt     time.Time

	status   Status
	org      Organization
	services []string
	code     string
	token    string
}

// Params are the immutable inputs captured when an issuance starts.
type Params struct {
	ID            string
	RedirectURI   string
	OAuthState    string
	CodeChallenge string
	ConfigID      string
	Recipient     Recipient
}

// New starts a new issuance in the Started state.
func New(p Params, now time.Time) *Issuance {
	return &Issuance{
		id:            p.ID,
		redirectURI:   p.RedirectURI,
		oauthState:    p.OAuthState,
		codeChallenge: p.CodeChallenge,
		configID:      p.ConfigID,
		recipient:     p.Recipient,
		createdAt:     now,
		status:        Started,
	}
}

// Authenticate records the authenticated organisation (Started -> Authenticated).
func (i *Issuance) Authenticate(org Organization) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != Started {
		return ErrInvalidState
	}
	i.org = org
	i.status = Authenticated
	return nil
}

// GrantConsent records the chosen services and binds an authorization code
// (Authenticated -> Consented).
func (i *Issuance) GrantConsent(services []string, code string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != Authenticated {
		return ErrInvalidState
	}
	i.services = services
	i.code = code
	i.status = Consented
	return nil
}

// ExchangeCode verifies PKCE and the redirect_uri and binds an access token
// (Consented -> Tokenized).
func (i *Issuance) ExchangeCode(verifier, redirectURI, token string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != Consented {
		return ErrInvalidState
	}
	if i.redirectURI != redirectURI {
		return ErrRedirectURIMismatch
	}
	if !verifyPKCE(verifier, i.codeChallenge) {
		return ErrPKCE
	}
	i.token = token
	i.status = Tokenized
	return nil
}

// MarkIssued records that the credential has been issued (Tokenized -> Issued).
func (i *Issuance) MarkIssued() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != Tokenized {
		return ErrInvalidState
	}
	i.status = Issued
	return nil
}

// Accessors. Each takes the lock so reads are consistent with transitions.

func (i *Issuance) ID() string           { i.mu.Lock(); defer i.mu.Unlock(); return i.id }
func (i *Issuance) RedirectURI() string  { i.mu.Lock(); defer i.mu.Unlock(); return i.redirectURI }
func (i *Issuance) OAuthState() string   { i.mu.Lock(); defer i.mu.Unlock(); return i.oauthState }
func (i *Issuance) ConfigID() string     { i.mu.Lock(); defer i.mu.Unlock(); return i.configID }
func (i *Issuance) Code() string         { i.mu.Lock(); defer i.mu.Unlock(); return i.code }
func (i *Issuance) Token() string        { i.mu.Lock(); defer i.mu.Unlock(); return i.token }
func (i *Issuance) Recipient() Recipient { i.mu.Lock(); defer i.mu.Unlock(); return i.recipient }
func (i *Issuance) Organization() Organization {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.org
}

// Services returns a copy of the chosen services.
func (i *Issuance) Services() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.services...)
}

// CreatedAt returns when the issuance started.
func (i *Issuance) CreatedAt() time.Time { i.mu.Lock(); defer i.mu.Unlock(); return i.createdAt }

func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}
