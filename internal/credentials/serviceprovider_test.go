package credentials

import (
	"testing"
	"time"
)

func TestBuildServiceProviderCredential(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	req := BuildServiceProviderCredential(
		"did:web:issuer.example.nl",
		ServiceProvider{
			DID:       "did:web:sp.example.nl",
			LegalName: "Voorbeeld Dienstverlener B.V.",
		},
		24*time.Hour,
		now,
	)

	if req.IssuerDID != "did:web:issuer.example.nl" {
		t.Errorf("issuer = %q", req.IssuerDID)
	}
	if got := req.Type; len(got) != 2 || got[0] != "VerifiableCredential" || got[1] != ServiceProviderCredentialType {
		t.Errorf("type = %v", got)
	}
	if req.Format != "jwt_vc" {
		t.Errorf("format = %q, want jwt_vc", req.Format)
	}
	if req.ExpirationDate != "2026-06-24T12:00:00Z" {
		t.Errorf("expirationDate = %q", req.ExpirationDate)
	}
	if len(req.Context) != 2 || req.Context[0] != "https://www.w3.org/2018/credentials/v1" {
		t.Errorf("@context = %v", req.Context)
	}

	subj := req.Subject
	if subj["id"] != "did:web:sp.example.nl" {
		t.Errorf("subject id = %v", subj["id"])
	}
	if subj["@type"] != "ServiceProvider" {
		t.Errorf("subject @type = %v", subj["@type"])
	}
	if subj["name"] != "Voorbeeld Dienstverlener B.V." {
		t.Errorf("subject name = %v", subj["name"])
	}
	services, _ := subj["services"].([]string)
	if len(services) != 1 || services[0] != "gbc-client" {
		t.Errorf("subject services = %v", subj["services"])
	}
}
