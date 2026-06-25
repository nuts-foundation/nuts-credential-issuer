// Package auth defines the swappable authentication seam of the issuer.
//
// An Authenticator is a self-contained HTTP module: it registers its own routes
// (the login page and the submission) on a mux, and calls back the Result it was
// given at construction once the user is authenticated. The issuer's OAuth
// adapter redirects the user to the authenticator's login route to begin. The
// demo ships a fake eHerkenning implementation (package eherkenning); real
// authentication can be dropped in behind the same interface.
package auth

import "net/http"

// Attributes are the authenticated subject's attributes that drive credential
// issuance.
type Attributes struct {
	// LegalName is the organisation's legal name.
	LegalName string
	// Identifier is the organisation identifier (e.g. KvK number).
	Identifier string
}

// Result is invoked once the user is authenticated. The issuer supplies it at
// the authenticator's construction to continue the flow (bind the attributes to
// the session and show consent). The session is carried out-of-band (a cookie set
// by the issuer), so the authenticator does not handle it.
type Result func(w http.ResponseWriter, r *http.Request, attrs Attributes)

// Authenticator authenticates the user interactively. It mounts its own HTTP
// handlers (login page + submission) on mux.
type Authenticator interface {
	RegisterRoutes(mux *http.ServeMux)
}
