package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// holder is a test fixture: a did:web holder whose DID document is served over
// HTTP and whose key can sign credential-request proofs.
type holder struct {
	did    string
	kid    string
	key    *ecdsa.PrivateKey
	server *httptest.Server
}

// newHolder starts an httptest server serving a did:web document at
// /.well-known/did.json and returns the holder fixture.
func newHolder(t *testing.T) *holder {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h := &holder{key: key}
	mux.HandleFunc("/.well-known/did.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.didDocument(t))
	})
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)

	u, _ := url.Parse(h.server.URL)
	// did:web requires the port colon to be percent-encoded as %3A.
	h.did = "did:web:" + strings.ReplaceAll(u.Host, ":", "%3A") // e.g. did:web:127.0.0.1%3A54321
	h.kid = h.did + "#0"
	return h
}

func (h *holder) didDocument(t *testing.T) map[string]any {
	t.Helper()
	pub, err := jwk.FromRaw(h.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	buf, _ := json.Marshal(pub)
	var jwkMap map[string]any
	_ = json.Unmarshal(buf, &jwkMap)
	return map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       h.did,
		"verificationMethod": []map[string]any{{
			"id":           h.kid,
			"type":         "JsonWebKey2020",
			"controller":   h.did,
			"publicKeyJwk": jwkMap,
		}},
		"assertionMethod": []string{h.kid},
	}
}

// proof builds a signed credential-request proof JWT.
func (h *holder) proof(t *testing.T, audience, nonce string, now time.Time) string {
	t.Helper()
	return h.proofWith(t, audience, nonce, now, "openid4vci-proof+jwt", h.kid)
}

func (h *holder) proofWith(t *testing.T, audience, nonce string, now time.Time, typ, kid string) string {
	t.Helper()
	builder := jwt.NewBuilder().Issuer(h.did).Audience([]string{audience}).IssuedAt(now)
	if nonce != "" {
		builder = builder.Claim("nonce", nonce)
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, typ)
	_ = hdrs.Set(jws.KeyIDKey, kid)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, h.key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

const testAudience = "https://issuer.example.nl"

func TestProofValidator_HappyPath(t *testing.T) {
	h := newHolder(t)
	now := time.Now()
	v := newProofValidator(testAudience, true, http.DefaultClient, func() time.Time { return now })

	gotDID, err := v.validate(context.Background(), h.proof(t, testAudience, "nonce-1", now), nonceAlways(true))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if gotDID != h.did {
		t.Errorf("holder DID = %q, want %q", gotDID, h.did)
	}
}

func TestProofValidator_Rejections(t *testing.T) {
	h := newHolder(t)
	now := time.Now()
	v := newProofValidator(testAudience, true, http.DefaultClient, func() time.Time { return now })

	tests := []struct {
		name      string
		proof     string
		nonceOK   func(string) bool
		wantSubst string
	}{
		{
			name:      "wrong typ",
			proof:     h.proofWith(t, testAudience, "n", now, "jwt", h.kid),
			nonceOK:   nonceAlways(true),
			wantSubst: "typ",
		},
		{
			name:      "wrong audience",
			proof:     h.proof(t, "https://someone-else.example", "n", now),
			nonceOK:   nonceAlways(true),
			wantSubst: "verification failed",
		},
		{
			name:      "unknown nonce",
			proof:     h.proof(t, testAudience, "n", now),
			nonceOK:   nonceAlways(false),
			wantSubst: "nonce",
		},
		{
			name:      "missing nonce",
			proof:     h.proof(t, testAudience, "", now),
			nonceOK:   nonceAlways(true),
			wantSubst: "nonce",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.validate(context.Background(), tc.proof, tc.nonceOK)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSubst) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSubst)
			}
		})
	}
}

func TestProofValidator_WrongKeyFails(t *testing.T) {
	h := newHolder(t) // publishes h.key in its DID document
	now := time.Now()
	v := newProofValidator(testAudience, true, http.DefaultClient, func() time.Time { return now })

	// Sign a proof for h's DID/kid with a foreign key, so the signature cannot
	// verify against the published verification method.
	foreignKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreign := &holder{did: h.did, kid: h.kid, key: foreignKey, server: h.server}

	_, err := v.validate(context.Background(), foreign.proof(t, testAudience, "n", now), nonceAlways(true))
	if err == nil {
		t.Fatal("expected signature verification to fail with a foreign key")
	}
}

func nonceAlways(ok bool) func(string) bool {
	return func(string) bool { return ok }
}
