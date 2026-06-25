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

// Snapshot is a point-in-time copy of an Issuance's data.
type Snapshot struct {
	ID        string
	ConfigID  string
	Recipient Recipient
	Status    Status
	CreatedAt time.Time

	Organization Organization
	Services     []string
	HolderDID    string
}

// Issuance is the aggregate root of one issuance flow.
type Issuance struct {
	mu   sync.Mutex
	snap Snapshot
}

// Params are the immutable inputs captured when an issuance starts.
type Params struct {
	ID        string
	ConfigID  string
	Recipient Recipient
}

// New starts a new issuance awaiting authentication.
func New(p Params, now time.Time) *Issuance {
	return &Issuance{snap: Snapshot{
		ID:        p.ID,
		ConfigID:  p.ConfigID,
		Recipient: p.Recipient,
		Status:    AwaitingAuthentication,
		CreatedAt: now,
	}}
}

// Authenticate records the authenticated organisation
// (AwaitingAuthentication -> AwaitingConsent).
func (i *Issuance) Authenticate(org Organization) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.snap.Status != AwaitingAuthentication {
		return ErrInvalidState
	}
	i.snap.Organization = org
	i.snap.Status = AwaitingConsent
	return nil
}

// Consent records the chosen services (AwaitingConsent -> Consented).
func (i *Issuance) Consent(services []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.snap.Status != AwaitingConsent {
		return ErrInvalidState
	}
	i.snap.Services = services
	i.snap.Status = Consented
	return nil
}

// Issue records the holder the credential is bound to (Consented -> Issued).
func (i *Issuance) Issue(holderDID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.snap.Status != Consented {
		return ErrInvalidState
	}
	i.snap.HolderDID = holderDID
	i.snap.Status = Issued
	return nil
}

// Snapshot returns a copy of the issuance's data.
func (i *Issuance) Snapshot() Snapshot {
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.snap
	s.Services = append([]string(nil), i.snap.Services...)
	return s
}

// ID returns the issuance id (the in-flight session identity).
func (i *Issuance) ID() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.snap.ID
}

// CreatedAt returns when the issuance started.
func (i *Issuance) CreatedAt() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.snap.CreatedAt
}
