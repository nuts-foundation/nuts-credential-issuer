package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
)

func TestConsentRendersRecipient(t *testing.T) {
	r, err := New("Test Issuer")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := r.Consent(rec, openid4vci.ConsentData{
		SessionID:       "sess-1",
		PostPath:        "/consent",
		OrgName:         "Voorbeeld B.V.",
		OrgIdentifier:   "90000001",
		CredentialType:  "ServiceProviderCredential",
		Recipient:       "wallet.example.nl:8080",
		RecipientDetail: "oauth2/wallet",
	}); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Voorbeeld B.V.", "ServiceProviderCredential", "wallet.example.nl:8080", "oauth2/wallet",
		`name="session" value="sess-1"`, `action="/consent"`, "Test Issuer", `name="services"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page missing %q", want)
		}
	}
}

func TestRedirectAndErrorRender(t *testing.T) {
	r, err := New("Test Issuer")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := r.Redirect(rec, openid4vci.RedirectData{Action: "http://localhost:8080/cb", Code: "c", State: "s"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), `action="http://localhost:8080/cb"`) {
		t.Error("redirect page missing action")
	}
	rec2 := httptest.NewRecorder()
	r.Error(rec2, 400, "boom")
	if !strings.Contains(rec2.Body.String(), "boom") {
		t.Error("error page missing message")
	}
}
