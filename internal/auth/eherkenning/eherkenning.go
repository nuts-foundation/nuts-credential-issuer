// Package eherkenning is the demo authenticator: a fake eHerkenning login. It
// owns its own login page (embedded template) and registers its own HTTP
// handler. The login form is pre-filled with a configured organisation identity
// but is editable, so a tester can issue to any organisation.
//
// It is NOT a real authentication method: it performs no identity proofing and
// must never run in a hosted deployment. The caller decides whether to construct
// it (gated on a demo flag), so the fake login can never be the default.
package eherkenning

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
)

// LoginPath is where the login form is served and submitted.
const LoginPath = "/login"

//go:embed templates/login.html
var templatesFS embed.FS

// Authenticator is the fake eHerkenning authenticator.
type Authenticator struct {
	defaultLegalName  string
	defaultIdentifier string
	title             string
	tmpl              *template.Template
}

// New constructs the fake eHerkenning authenticator. legalName and identifier
// are the defaults pre-filled in the (editable) login form; title is the issuer
// display name shown on the page.
func New(defaultLegalName, defaultIdentifier, title string) (*Authenticator, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		defaultLegalName:  defaultLegalName,
		defaultIdentifier: defaultIdentifier,
		title:             title,
		tmpl:              tmpl,
	}, nil
}

// RegisterRoutes mounts the login submission handler on mux.
func (a *Authenticator) RegisterRoutes(mux *http.ServeMux, result auth.Result) {
	mux.HandleFunc("POST "+LoginPath, func(w http.ResponseWriter, r *http.Request) {
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
		result(w, r, r.FormValue("session"), auth.Attributes{LegalName: legalName, Identifier: identifier})
	})
}

type loginData struct {
	Session    string
	Action     string
	Title      string
	LegalName  string
	Identifier string
}

// Start renders the (editable) fake login page for the given session.
func (a *Authenticator) Start(w http.ResponseWriter, _ *http.Request, session string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return a.tmpl.Execute(w, loginData{
		Session:    session,
		Action:     LoginPath,
		Title:      a.title,
		LegalName:  a.defaultLegalName,
		Identifier: a.defaultIdentifier,
	})
}
