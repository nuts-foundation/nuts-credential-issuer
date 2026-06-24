// Package web renders the issuer's HTML pages from embedded htmx templates. It
// implements the application's Presenter port.
package web

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Renderer renders the issuer's pages (consent, redirect, error). The login page
// lives with its authenticator (see the eherkenning package).
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

type consentPage struct {
	SessionID       string
	PostPath        string
	CredentialType  string
	OrgName         string
	OrgIdentifier   string
	Recipient       string
	RecipientDetail string
	Services        string
}

// Consent renders the consent page.
func (r *Renderer) Consent(w http.ResponseWriter, v issuer.ConsentView) error {
	return r.render(w, http.StatusOK, "consent.html", consentPage{
		SessionID:       v.SessionID,
		PostPath:        issuer.ConsentPath,
		CredentialType:  v.CredentialType,
		OrgName:         v.Organization.LegalName,
		OrgIdentifier:   v.Organization.Identifier,
		Recipient:       v.Recipient.Host,
		RecipientDetail: v.Recipient.Detail,
		Services:        strings.Join(v.Services, ", "),
	})
}

// Redirect renders the auto-submitting form that returns the authorization code
// to the wallet's redirect_uri.
func (r *Renderer) Redirect(w http.ResponseWriter, v issuer.RedirectView) error {
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

// Ensure *Renderer satisfies the application's Presenter port.
var _ issuer.Presenter = (*Renderer)(nil)
