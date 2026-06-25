package proof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
)

const testAudience = "https://issuer.example.nl"

// holder is a test fixture: a did:web holder whose document and signing key are
// held in memory.
type holder struct {
	did string
	kid string
	key *ecdsa.PrivateKey
	doc *did.Document
}

func newHolder(t *testing.T) *holder {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &holder{
		did: "did:web:wallet.example.nl",
		key: key,
	}
	h.kid = h.did + "#0"

	pub, err := jwk.FromRaw(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	buf, _ := json.Marshal(pub)
	var jwkMap map[string]any
	_ = json.Unmarshal(buf, &jwkMap)
	docJSON, _ := json.Marshal(map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       h.did,
		"verificationMethod": []map[string]any{{
			"id":           h.kid,
			"type":         "JsonWebKey2020",
			"controller":   h.did,
			"publicKeyJwk": jwkMap,
		}},
		"assertionMethod": []string{h.kid},
	})
	var doc did.Document
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		t.Fatal(err)
	}
	h.doc = &doc
	return h
}

func (h *holder) proof(t *testing.T, audience, nonce string, now time.Time) string {
	t.Helper()
	return h.proofWith(t, audience, nonce, now, JWTType, h.kid, h.key)
}

func (h *holder) proofWith(t *testing.T, audience, nonce string, now time.Time, typ, kid string, key *ecdsa.PrivateKey) string {
	t.Helper()
	b := jwt.NewBuilder().Issuer(h.did).Audience([]string{audience}).IssuedAt(now)
	if nonce != "" {
		b = b.Claim("nonce", nonce)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, typ)
	_ = hdrs.Set(jws.KeyIDKey, kid)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// fakeResolver returns a fixed set of DID documents.
type fakeResolver map[string]*did.Document

func (r fakeResolver) Resolve(_ context.Context, didStr string) (*did.Document, error) {
	doc, ok := r[didStr]
	if !ok {
		return nil, errNotFound
	}
	return doc, nil
}

var errNotFound = &resolveErr{}

type resolveErr struct{}

func (*resolveErr) Error() string { return "DID not found" }

func TestVerify_HappyPath(t *testing.T) {
	h := newHolder(t)
	now := time.Now()
	v := NewVerifier(fakeResolver{h.did: h.doc}, testAudience, func() time.Time { return now })

	res, err := v.Verify(context.Background(), h.proof(t, testAudience, "nonce-1", now))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.HolderDID != h.did {
		t.Errorf("holder DID = %q, want %q", res.HolderDID, h.did)
	}
	if res.Nonce != "nonce-1" {
		t.Errorf("nonce = %q, want nonce-1", res.Nonce)
	}
}

func TestVerify_Rejections(t *testing.T) {
	h := newHolder(t)
	now := time.Now()
	v := NewVerifier(fakeResolver{h.did: h.doc}, testAudience, func() time.Time { return now })

	foreign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name      string
		token     string
		wantSubst string
	}{
		{"wrong typ", h.proofWith(t, testAudience, "n", now, "jwt", h.kid, h.key), "typ"},
		{"wrong audience", h.proof(t, "https://someone-else.example", "n", now), "verification failed"},
		{"foreign key", h.proofWith(t, testAudience, "n", now, JWTType, h.kid, foreign), "verification failed"},
		{"missing nonce", h.proof(t, testAudience, "", now), "nonce"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.token)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSubst) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSubst)
			}
		})
	}
}
