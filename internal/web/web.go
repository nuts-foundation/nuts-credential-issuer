// Package web renders the issuer's HTML pages from embedded htmx templates. Its
// view models are plain data; the inbound adapter maps to them, so web has no
// dependency on the application or protocol packages.
package web

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

// ConsentView is the consent page model.
type ConsentView struct {
	SessionID       string
	PostPath        string
	CredentialType  string
	OrgName         string
	OrgIdentifier   string
	Recipient       string // wallet host
	RecipientDetail string // wallet path/identifier
	Services        string
}

// RedirectView is the auto-submit redirect page model.
type RedirectView struct {
	Action string
	Code   string
	State  string
}

// Renderer renders the issuer's pages. The login page lives with its
// authenticator (see the eherkenning package).
type Renderer struct {
	tmpl *template.Template
}

// New parses the embedded templates. title is the issuer display name shown in
// the UI.
func New(title string) (*Renderer, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"appTitle": func() string { return title },
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Renderer{tmpl: tmpl}, nil
}

// Consent renders the consent page.
func (r *Renderer) Consent(w http.ResponseWriter, v ConsentView) error {
	return r.render(w, http.StatusOK, "consent.html", v)
}

// Redirect renders the auto-submitting form that returns the authorization code
// to the wallet's redirect_uri.
func (r *Renderer) Redirect(w http.ResponseWriter, v RedirectView) error {
	return r.render(w, http.StatusOK, "redirect.html", v)
}

// Error renders an error page.
func (r *Renderer) Error(w http.ResponseWriter, status int, message string) {
	_ = r.render(w, status, "error.html", map[string]any{"Message": message})
}

func (r *Renderer) render(w http.ResponseWriter, status int, name string, data any) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	return r.tmpl.ExecuteTemplate(w, name, data)
}
