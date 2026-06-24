package openid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
)

// proofJWTType is the required "typ" header of an OpenID4VCI credential-request
// proof JWT.
const proofJWTType = "openid4vci-proof+jwt"

// proofValidator validates OpenID4VCI credential-request proofs and resolves the
// holder DID they bind to.
type proofValidator struct {
	// audience is the Credential Issuer Identifier the proof's "aud" must match.
	audience string
	// insecure allows resolving did:web over plain HTTP (demo only).
	insecure bool
	http     *http.Client
	now      func() time.Time
}

func newProofValidator(audience string, insecure bool, httpClient *http.Client, now func() time.Time) *proofValidator {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &proofValidator{audience: audience, insecure: insecure, http: httpClient, now: now}
}

// validate checks the proof JWT and, on success, returns the holder DID taken
// from the proof's "kid". nonceValid reports whether the proof's nonce claim was
// one this issuer handed out.
func (v *proofValidator) validate(ctx context.Context, token string, nonceValid func(string) bool) (string, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return "", fmt.Errorf("proof is not a valid JWS: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return "", fmt.Errorf("proof must have exactly one signature")
	}
	hdr := sigs[0].ProtectedHeaders()

	if hdr.Type() != proofJWTType {
		return "", fmt.Errorf("proof has wrong typ header %q, want %q", hdr.Type(), proofJWTType)
	}
	alg := hdr.Algorithm()
	if alg == "" || alg == jwa.NoSignature {
		return "", fmt.Errorf("proof must be signed")
	}
	kid := hdr.KeyID()
	if kid == "" {
		return "", fmt.Errorf("proof is missing kid header")
	}

	kidURL, err := did.ParseDIDURL(kid)
	if err != nil {
		return "", fmt.Errorf("proof kid is not a DID URL: %w", err)
	}
	holderDID := kidURL.DID
	if holderDID.Method != "web" {
		return "", fmt.Errorf("unsupported holder DID method %q, only did:web is supported", holderDID.Method)
	}

	key, err := v.resolveKey(ctx, holderDID, *kidURL)
	if err != nil {
		return "", fmt.Errorf("resolve holder key: %w", err)
	}

	// Verify the signature and validate the claims. aud must be the Credential
	// Issuer Identifier; iat must be present; exp is not required.
	if _, err := jwt.Parse([]byte(token),
		jwt.WithKey(alg, key),
		jwt.WithValidate(true),
		jwt.WithAudience(v.audience),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithAcceptableSkew(5*time.Second),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	); err != nil {
		return "", fmt.Errorf("proof verification failed: %w", err)
	}

	// The nonce binds the proof to a c_nonce this issuer issued.
	nonce, err := nonceClaim(token)
	if err != nil {
		return "", err
	}
	if !nonceValid(nonce) {
		return "", fmt.Errorf("proof nonce is missing, unknown or expired")
	}
	return holderDID.String(), nil
}

func nonceClaim(token string) (string, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return "", fmt.Errorf("parse proof claims: %w", err)
	}
	raw, ok := parsed.Get("nonce")
	if !ok {
		return "", fmt.Errorf("proof is missing nonce claim")
	}
	nonce, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("proof nonce claim is not a string")
	}
	return nonce, nil
}

// resolveKey resolves the did:web document for holder and returns the public key
// for the given verification method id.
func (v *proofValidator) resolveKey(ctx context.Context, holder did.DID, kid did.DIDURL) (any, error) {
	docURL, err := didWebDocumentURL(holder, v.insecure)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", docURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web resolution of %s returned HTTP %d", docURL, resp.StatusCode)
	}
	var doc did.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}
	vm := doc.VerificationMethod.FindByID(kid)
	if vm == nil {
		vm = doc.AssertionMethod.FindByID(kid)
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

// didWebDocumentURL converts a did:web DID to the URL of its DID document, per
// the did:web method spec.
func didWebDocumentURL(d did.DID, insecure bool) (string, error) {
	if d.Method != "web" {
		return "", fmt.Errorf("not a did:web: %s", d.String())
	}
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	parts := strings.Split(d.ID, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid did:web host: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("did:web has empty host")
	}
	if len(parts) == 1 {
		return scheme + "://" + host + "/.well-known/did.json", nil
	}
	segments := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		seg, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("invalid did:web path segment: %w", err)
		}
		segments = append(segments, seg)
	}
	return scheme + "://" + host + "/" + strings.Join(segments, "/") + "/did.json", nil
}
