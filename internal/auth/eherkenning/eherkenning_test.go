package eherkenning

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
)

func noopResult(http.ResponseWriter, *http.Request, auth.Attributes) {}

func TestNew_RequiresResult(t *testing.T) {
	if _, err := New("Org", "1", "Title", nil); err == nil {
		t.Error("New must require a result callback")
	}
}

func TestStart_RendersEditableDefaults(t *testing.T) {
	a, err := New("Voorbeeld B.V.", "90000001", "Test Issuer", noopResult)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	body := rec.Body.String()
	for _, want := range []string{`value="Voorbeeld B.V."`, `value="90000001"`, `name="legal_name"`, `name="identifier"`, "Test Issuer"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q:\n%s", want, body)
		}
	}
}

func TestSubmit_UsesSubmittedValues(t *testing.T) {
	var gotAttrs auth.Attributes
	a, _ := New("Default B.V.", "90000001", "T", func(w http.ResponseWriter, r *http.Request, attrs auth.Attributes) {
		gotAttrs = attrs
	})
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)

	form := url.Values{"legal_name": {"Andere B.V."}, "identifier": {"12345678"}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if gotAttrs.LegalName != "Andere B.V." || gotAttrs.Identifier != "12345678" {
		t.Errorf("attrs = %+v, want submitted values", gotAttrs)
	}
}

func TestSubmit_FallsBackToDefaults(t *testing.T) {
	var gotAttrs auth.Attributes
	a, _ := New("Default B.V.", "90000001", "T", func(w http.ResponseWriter, r *http.Request, attrs auth.Attributes) {
		gotAttrs = attrs
	})
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(url.Values{}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if gotAttrs.LegalName != "Default B.V." || gotAttrs.Identifier != "90000001" {
		t.Errorf("attrs = %+v, want defaults", gotAttrs)
	}
}
