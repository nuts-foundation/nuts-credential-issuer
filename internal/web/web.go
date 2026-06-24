// Package web renders the issuer's HTML pages (login, consent and the
// auto-submit redirect) from embedded htmx templates.
package web

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Renderer renders the issuer's pages (consent, redirect, error). It implements
// openid4vci.Renderer. The login page lives with its authenticator (see the
// eherkenning package).
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
func (r *Renderer) Consent(w http.ResponseWriter, data openid4vci.ConsentData) error {
	return r.render(w, http.StatusOK, "consent.html", data)
}

// Redirect renders the auto-submitting form that returns the authorization code
// to the wallet's redirect_uri.
func (r *Renderer) Redirect(w http.ResponseWriter, data openid4vci.RedirectData) error {
	return r.render(w, http.StatusOK, "redirect.html", data)
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

// Ensure *Renderer satisfies the issuer's Renderer interface.
var _ openid4vci.Renderer = (*Renderer)(nil)
