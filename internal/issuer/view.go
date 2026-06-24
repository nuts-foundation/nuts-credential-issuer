package issuer

import (
	"errors"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// ConsentPath is where the consent form is submitted. It is part of the flow
// contract shared by the HTTP adapter (routing) and the web presenter (form action).
const ConsentPath = "/consent"

// AuthorizeParams are the inputs to start an issuance, parsed from the
// authorization request by the transport adapter.
type AuthorizeParams struct {
	RedirectURI   string
	OAuthState    string
	CodeChallenge string
	// RequestedConfigID is the credential_configuration_id the wallet asked for,
	// or "" when it left the choice open.
	RequestedConfigID string
	Recipient         issuance.Recipient
}

// ConsentView is the data the consent page needs.
type ConsentView struct {
	SessionID      string
	CredentialType string
	Organization   issuance.Organization
	Recipient      issuance.Recipient
	// Services is the default set to prefill the (editable) services field.
	Services []string
}

// RedirectView returns the authorization code to the wallet's redirect_uri.
type RedirectView struct {
	Action string
	Code   string
	State  string
}

// TokenResult is the result of a successful token exchange.
type TokenResult struct {
	AccessToken string
	CNonce      string
	ExpiresIn   int
}

// Application-level errors the transport adapter maps to protocol responses.
var (
	// ErrUnsupportedCredential is returned for a credential the issuer does not offer.
	ErrUnsupportedCredential = errors.New("unsupported credential")
	// ErrSessionNotFound is returned when an issuance/session is unknown or expired.
	ErrSessionNotFound = errors.New("unknown or expired session")
	// ErrInvalidGrant is returned for a bad token exchange (unknown code, PKCE, redirect).
	ErrInvalidGrant = errors.New("invalid grant")
	// ErrInvalidToken is returned for an unknown/expired access token.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidProof is returned when the credential-request proof fails validation.
	ErrInvalidProof = errors.New("invalid proof")
)
