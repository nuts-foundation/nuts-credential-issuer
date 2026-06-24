// Package issuer is the application layer: it orchestrates the credential
// issuance use-cases over the domain (issuance) and a set of ports. It has no
// HTTP/transport knowledge; the OpenID4VCI adapter drives it.
package issuer

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
)

// Store persists issuances and the c_nonces handed out for proofs.
type Store interface {
	Create(iss *issuance.Issuance)
	Get(id string) (*issuance.Issuance, bool)
	BindCode(code, id string)
	TakeByCode(code string) (*issuance.Issuance, bool)
	BindToken(token, id string)
	ByToken(token string) (*issuance.Issuance, bool)
	PutNonce(nonce string)
	ConsumeNonce(nonce string) bool
}

// Minter mints a credential (e.g. via a Nuts node) and returns it verbatim.
type Minter interface {
	IssueVC(ctx context.Context, cred credentials.Credential) (json.RawMessage, error)
}

// SubjectResolver resolves the issuer's did:web from its Nuts subject.
type SubjectResolver interface {
	SubjectDID(ctx context.Context, subject string) (string, error)
}

// ProofVerifier cryptographically verifies a credential-request proof.
type ProofVerifier interface {
	Verify(ctx context.Context, token string) (proof.Result, error)
}

// Presenter renders the issuer's HTML pages. It is implemented by the web
// adapter and used by the OpenID4VCI adapter.
type Presenter interface {
	Consent(w http.ResponseWriter, v ConsentView) error
	Redirect(w http.ResponseWriter, v RedirectView) error
	Error(w http.ResponseWriter, status int, message string)
}
