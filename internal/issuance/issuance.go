// Package issuance is the domain model for one credential-issuance flow.
//
// An Issuance is an aggregate with an explicit business state machine:
// AwaitingAuthentication -> AwaitingConsent -> Consented -> Issued. It knows
// nothing about OAuth/OpenID4VCI (codes, tokens, PKCE, nonces) — those are
// transport concerns owned by the inbound adapter. All access is synchronised.
package issuance

import (
	"errors"
	"sync"
	"time"
)

// Status is the lifecycle state of an Issuance.
type Status int

const (
	AwaitingAuthentication Status = iota // started, awaiting authentication
	AwaitingConsent                      // authenticated, awaiting consent
	Consented                            // consent granted, ready to issue
	Issued                               // credential issued (terminal)
)

// ErrInvalidState is returned when a transition is attempted from the wrong state.
var ErrInvalidState = errors.New("invalid issuance state for this operation")

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

	id        string
	configID  string
	recipient Recipient
	createdAt time.Time

	status    Status
	org       Organization
	services  []string
	holderDID string
}

// Params are the immutable inputs captured when an issuance starts.
type Params struct {
	ID        string
	ConfigID  string
	Recipient Recipient
}

// New starts a new issuance awaiting authentication.
func New(p Params, now time.Time) *Issuance {
	return &Issuance{
		id:        p.ID,
		configID:  p.ConfigID,
		recipient: p.Recipient,
		createdAt: now,
		status:    AwaitingAuthentication,
	}
}

// Authenticate records the authenticated organisation
// (AwaitingAuthentication -> AwaitingConsent).
func (i *Issuance) Authenticate(org Organization) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != AwaitingAuthentication {
		return ErrInvalidState
	}
	i.org = org
	i.status = AwaitingConsent
	return nil
}

// Consent records the chosen services (AwaitingConsent -> Consented).
func (i *Issuance) Consent(services []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != AwaitingConsent {
		return ErrInvalidState
	}
	i.services = services
	i.status = Consented
	return nil
}

// Issue records the holder the credential is bound to (Consented -> Issued).
func (i *Issuance) Issue(holderDID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != Consented {
		return ErrInvalidState
	}
	i.holderDID = holderDID
	i.status = Issued
	return nil
}

// Accessors. Each takes the lock so reads are consistent with transitions.

func (i *Issuance) ID() string           { i.mu.Lock(); defer i.mu.Unlock(); return i.id }
func (i *Issuance) ConfigID() string     { i.mu.Lock(); defer i.mu.Unlock(); return i.configID }
func (i *Issuance) Recipient() Recipient { i.mu.Lock(); defer i.mu.Unlock(); return i.recipient }
func (i *Issuance) HolderDID() string    { i.mu.Lock(); defer i.mu.Unlock(); return i.holderDID }
func (i *Issuance) CreatedAt() time.Time { i.mu.Lock(); defer i.mu.Unlock(); return i.createdAt }
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
