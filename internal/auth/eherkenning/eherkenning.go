// Package eherkenning is the demo authenticator: a fake eHerkenning login. It is
// a self-contained HTTP module — it registers its own login page (GET) and
// submission (POST), and calls back the Result it was given at construction. The
// login form is pre-filled with a configured organisation identity but editable,
// so a tester can issue to any organisation.
//
// It is NOT a real authentication method: it performs no identity proofing and
// must never run in a hosted deployment. The caller decides whether to construct
// it (gated on a demo flag).
package eherkenning

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
)

// LoginPath is where the login page is served and submitted; the issuer's OAuth
// adapter redirects the user here to begin authentication.
const LoginPath = "/login"

//go:embed templates/login.html
var templatesFS embed.FS

// Authenticator is the fake eHerkenning authenticator.
type Authenticator struct {
	defaultLegalName  string
	defaultIdentifier string
	title             string
	tmpl              *template.Template
	result            auth.Result
}

// New constructs the fake eHerkenning authenticator. legalName and identifier are
// the defaults pre-filled in the (editable) login form; title is the issuer
// display name; result is invoked once the user submits the login.
func New(defaultLegalName, defaultIdentifier, title string, result auth.Result) (*Authenticator, error) {
	if result == nil {
		return nil, errors.New("result callback is required")
	}
	tmpl, err := template.ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		defaultLegalName:  defaultLegalName,
		defaultIdentifier: defaultIdentifier,
		title:             title,
		tmpl:              tmpl,
		result:            result,
	}, nil
}

// RegisterRoutes mounts the login page and submission handlers.
func (a *Authenticator) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+LoginPath, a.handleStart)
	mux.HandleFunc("POST "+LoginPath, a.handleSubmit)
}

type loginData struct {
	Action     string
	Title      string
	LegalName  string
	Identifier string
}

// handleStart renders the (editable) login page. The session is carried by a
// cookie the issuer set, so it is not handled here.
func (a *Authenticator) handleStart(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.Execute(w, loginData{
		Action:     LoginPath,
		Title:      a.title,
		LegalName:  a.defaultLegalName,
		Identifier: a.defaultIdentifier,
	}); err != nil {
		slog.Error("failed to render login page", "err", err)
	}
}

// handleSubmit yields the (editable) organisation identity to the Result callback.
func (a *Authenticator) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	legalName := strings.TrimSpace(r.FormValue("legal_name"))
	if legalName == "" {
		legalName = a.defaultLegalName
	}
	identifier := strings.TrimSpace(r.FormValue("identifier"))
	if identifier == "" {
		identifier = a.defaultIdentifier
	}
	a.result(w, r, auth.Attributes{LegalName: legalName, Identifier: identifier})
}
