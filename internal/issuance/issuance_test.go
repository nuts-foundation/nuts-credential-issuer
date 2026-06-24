package issuance

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func started() *Issuance {
	return New(Params{
		ID:            "id-1",
		RedirectURI:   "http://wallet/cb",
		OAuthState:    "st",
		CodeChallenge: challengeFor("verifier-123"),
		ConfigID:      "ServiceProviderCredential",
		Recipient:     Recipient{Host: "wallet:8080", Detail: "oauth2/w"},
	}, time.Now())
}

func TestHappyPathTransitions(t *testing.T) {
	i := started()
	if err := i.Authenticate(Organization{LegalName: "Acme", Identifier: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := i.GrantConsent([]string{"gbc-client"}, "code-1"); err != nil {
		t.Fatal(err)
	}
	if i.Code() != "code-1" {
		t.Errorf("code = %q", i.Code())
	}
	if err := i.ExchangeCode("verifier-123", "http://wallet/cb", "tok-1"); err != nil {
		t.Fatal(err)
	}
	if i.Token() != "tok-1" {
		t.Errorf("token = %q", i.Token())
	}
	if err := i.MarkIssued(); err != nil {
		t.Fatal(err)
	}
	if i.Organization().LegalName != "Acme" || len(i.Services()) != 1 {
		t.Errorf("org/services not retained: %+v %v", i.Organization(), i.Services())
	}
}

func TestOutOfOrderRejected(t *testing.T) {
	i := started()
	// Consent before authentication.
	if err := i.GrantConsent(nil, "c"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("consent before auth: got %v, want ErrInvalidState", err)
	}
	// Token before consent.
	if err := i.ExchangeCode("verifier-123", "http://wallet/cb", "t"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("token before consent: got %v, want ErrInvalidState", err)
	}
	// Issue before token.
	if err := i.MarkIssued(); !errors.Is(err, ErrInvalidState) {
		t.Errorf("issue before token: got %v, want ErrInvalidState", err)
	}
}

func TestExchangeCodeChecks(t *testing.T) {
	build := func() *Issuance {
		i := started()
		_ = i.Authenticate(Organization{})
		_ = i.GrantConsent(nil, "c")
		return i
	}
	if err := build().ExchangeCode("wrong", "http://wallet/cb", "t"); !errors.Is(err, ErrPKCE) {
		t.Errorf("bad verifier: got %v, want ErrPKCE", err)
	}
	if err := build().ExchangeCode("verifier-123", "http://evil/cb", "t"); !errors.Is(err, ErrRedirectURIMismatch) {
		t.Errorf("bad redirect: got %v, want ErrRedirectURIMismatch", err)
	}
}
