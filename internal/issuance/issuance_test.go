package issuance

import (
	"errors"
	"testing"
	"time"
)

func started() *Issuance {
	return New(Params{
		ID:        "id-1",
		ConfigID:  "ServiceProviderCredential",
		Recipient: Recipient{Host: "wallet:8080", Detail: "oauth2/w"},
	}, time.Now())
}

func TestHappyPathTransitions(t *testing.T) {
	i := started()
	if err := i.Authenticate(Organization{LegalName: "Acme", Identifier: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := i.Consent([]string{"gbc-client"}); err != nil {
		t.Fatal(err)
	}
	if err := i.Issue("did:web:holder"); err != nil {
		t.Fatal(err)
	}
	snap := i.Snapshot()
	if snap.Organization.LegalName != "Acme" || len(snap.Services) != 1 || snap.HolderDID != "did:web:holder" || snap.Status != Issued {
		t.Errorf("state not retained: %+v", snap)
	}
}

func TestOutOfOrderRejected(t *testing.T) {
	i := started()
	if err := i.Consent(nil); !errors.Is(err, ErrInvalidState) {
		t.Errorf("consent before auth: got %v, want ErrInvalidState", err)
	}
	if err := i.Issue("did:web:h"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("issue before consent: got %v, want ErrInvalidState", err)
	}
	_ = i.Authenticate(Organization{})
	if err := i.Authenticate(Organization{}); !errors.Is(err, ErrInvalidState) {
		t.Errorf("double authenticate: got %v, want ErrInvalidState", err)
	}
}
