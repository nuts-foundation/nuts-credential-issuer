// Package proof verifies OpenID4VCI credential-request proofs.
//
// It performs only cryptographic verification (signature, typ, audience, iat)
// and resolves the holder DID via a DIDResolver port. Replay/nonce state is left
// to the caller: Verify returns the proof's nonce so the application can check it
// against the c_nonces it issued.
package proof

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
)

// JWTType is the required "typ" header of an OpenID4VCI credential-request proof.
const JWTType = "openid4vci-proof+jwt"

// DIDResolver resolves a DID to its document.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*did.Document, error)
}

// Verifier verifies credential-request proofs against an expected audience.
type Verifier struct {
	resolver DIDResolver
	audience string
	now      func() time.Time
}

// NewVerifier returns a Verifier. audience is the Credential Issuer Identifier
// the proof's "aud" must match.
func NewVerifier(resolver DIDResolver, audience string, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{resolver: resolver, audience: audience, now: now}
}

// Result is the outcome of a successful verification.
type Result struct {
	// HolderDID is the DID the proof binds to (from its kid).
	HolderDID string
	// Nonce is the proof's nonce claim; the caller checks it for replay.
	Nonce string
}

// Verify checks the proof's signature, typ, audience and iat, and resolves the
// holder DID. It does NOT check the nonce for replay — that is returned for the
// caller to validate.
func (v *Verifier) Verify(ctx context.Context, token string) (Result, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return Result{}, fmt.Errorf("proof is not a valid JWS: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return Result{}, fmt.Errorf("proof must have exactly one signature")
	}
	hdr := sigs[0].ProtectedHeaders()

	if hdr.Type() != JWTType {
		return Result{}, fmt.Errorf("proof has wrong typ header %q, want %q", hdr.Type(), JWTType)
	}
	alg := hdr.Algorithm()
	if alg == "" || alg == jwa.NoSignature {
		return Result{}, fmt.Errorf("proof must be signed")
	}
	kid := hdr.KeyID()
	if kid == "" {
		return Result{}, fmt.Errorf("proof is missing kid header")
	}

	kidURL, err := did.ParseDIDURL(kid)
	if err != nil {
		return Result{}, fmt.Errorf("proof kid is not a DID URL: %w", err)
	}
	holderDID := kidURL.DID

	key, err := v.resolveKey(ctx, holderDID.String(), *kidURL)
	if err != nil {
		return Result{}, fmt.Errorf("resolve holder key: %w", err)
	}

	// Verify signature + claims. aud must be the Credential Issuer Identifier;
	// iat must be present; exp is not required.
	verified, err := jwt.Parse([]byte(token),
		jwt.WithKey(alg, key),
		jwt.WithValidate(true),
		jwt.WithAudience(v.audience),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithAcceptableSkew(5*time.Second),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	)
	if err != nil {
		return Result{}, fmt.Errorf("proof verification failed: %w", err)
	}

	nonce, err := nonceClaim(verified)
	if err != nil {
		return Result{}, err
	}
	return Result{HolderDID: holderDID.String(), Nonce: nonce}, nil
}

func (v *Verifier) resolveKey(ctx context.Context, holderDID string, kid did.DIDURL) (any, error) {
	doc, err := v.resolver.Resolve(ctx, holderDID)
	if err != nil {
		return nil, err
	}
	// Prefer the assertionMethod relationship (the proof asserts a credential),
	// falling back to the general verificationMethod set.
	vm := doc.AssertionMethod.FindByID(kid)
	if vm == nil {
		vm = doc.VerificationMethod.FindByID(kid)
	}
	if vm == nil {
		return nil, fmt.Errorf("verification method %s not found in DID document", kid.String())
	}
	key, err := vm.JWK()
	if err != nil {
		return nil, fmt.Errorf("read verification method key: %w", err)
	}
	return key, nil
}

func nonceClaim(token jwt.Token) (string, error) {
	raw, ok := token.Get("nonce")
	if !ok {
		return "", fmt.Errorf("proof is missing nonce claim")
	}
	nonce, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("proof nonce claim is not a string")
	}
	return nonce, nil
}
