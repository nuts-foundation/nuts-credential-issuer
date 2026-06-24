package eherkenning

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
)

func TestStart_RendersEditableDefaults(t *testing.T) {
	a, err := New("Voorbeeld B.V.", "90000001", "Test Issuer")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := a.Start(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil), "sess-42"); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	for _, want := range []string{`value="sess-42"`, `value="Voorbeeld B.V."`, `value="90000001"`, `name="legal_name"`, `name="identifier"`, "Test Issuer"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q:\n%s", want, body)
		}
	}
}

func TestRegisterRoutes_UsesSubmittedValues(t *testing.T) {
	a, _ := New("Default B.V.", "90000001", "Test Issuer")
	var gotSession string
	var gotAttrs auth.Attributes
	mux := http.NewServeMux()
	a.RegisterRoutes(mux, func(w http.ResponseWriter, r *http.Request, session string, attrs auth.Attributes) {
		gotSession, gotAttrs = session, attrs
	})

	form := url.Values{"session": {"sess-7"}, "legal_name": {"Andere B.V."}, "identifier": {"12345678"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)

	if gotSession != "sess-7" {
		t.Errorf("session = %q, want sess-7", gotSession)
	}
	if gotAttrs.LegalName != "Andere B.V." || gotAttrs.Identifier != "12345678" {
		t.Errorf("attrs = %+v, want submitted values", gotAttrs)
	}
}

func TestRegisterRoutes_FallsBackToDefaults(t *testing.T) {
	a, _ := New("Default B.V.", "90000001", "Test Issuer")
	var gotAttrs auth.Attributes
	mux := http.NewServeMux()
	a.RegisterRoutes(mux, func(w http.ResponseWriter, r *http.Request, session string, attrs auth.Attributes) {
		gotAttrs = attrs
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(url.Values{"session": {"s"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)

	if gotAttrs.LegalName != "Default B.V." || gotAttrs.Identifier != "90000001" {
		t.Errorf("attrs = %+v, want defaults", gotAttrs)
	}
}

func TestRegisterRoutes_RejectsGet(t *testing.T) {
	a, _ := New("Org", "1", "Test Issuer")
	mux := http.NewServeMux()
	a.RegisterRoutes(mux, func(http.ResponseWriter, *http.Request, string, auth.Attributes) {
		t.Fatal("result must not be called for a GET")
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
