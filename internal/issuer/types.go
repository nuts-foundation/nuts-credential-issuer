package issuer

import (
	"errors"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// StartParams are the business inputs to start an issuance.
type StartParams struct {
	// RequestedConfigID is the credential the caller asked for, or "" for the default.
	RequestedConfigID string
	// Recipient labels the wallet the credential will be issued to.
	Recipient issuance.Recipient
}

// ConsentDetails is what the consent step needs to present to the user.
type ConsentDetails struct {
	Organization   issuance.Organization
	Recipient      issuance.Recipient
	CredentialType string
	// Services is the default set offered (the user may edit it).
	Services []string
}

// ErrUnsupportedCredential is returned for a credential the issuer does not offer.
var ErrUnsupportedCredential = errors.New("unsupported credential")
