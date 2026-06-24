// Package issuer is the application layer: it orchestrates the credential
// issuance use-cases over the domain (issuance) and a small set of ports. It has
// no transport/protocol knowledge (no HTTP, no OAuth/OpenID4VCI) — the inbound
// adapter drives it and owns the protocol session.
package issuer

import (
	"context"
	"encoding/json"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
)

// Minter mints a credential (e.g. via a Nuts node) and returns it verbatim.
type Minter interface {
	Mint(ctx context.Context, cred credentials.Credential) (json.RawMessage, error)
}

// SubjectResolver resolves the issuer's did:web from its Nuts subject.
type SubjectResolver interface {
	SubjectDID(ctx context.Context, subject string) (string, error)
}
