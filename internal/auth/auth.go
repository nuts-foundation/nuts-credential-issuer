// Package auth defines the swappable authentication seam of the issuer.
//
// Authentication is interactive: the user logs in between the start and the
// result of the flow. An Authenticator owns its own UI and HTTP handlers; it
// registers them on a mux the issuer injects, and calls a Result continuation
// once authentication completes. The demo ships a fake eHerkenning
// implementation (package eherkenning); real authentication can be dropped in
// behind the same interface without touching the OpenID4VCI core.
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

// Result is invoked by an Authenticator once the user is authenticated. The
// issuer supplies it to continue the flow (bind the attributes to the session
// and show the credential selection). session is the OpenID4VCI session id that
// Start was given.
type Result func(w http.ResponseWriter, r *http.Request, session string, attrs Attributes)

// Authenticator authenticates the user interactively.
type Authenticator interface {
	// RegisterRoutes mounts the authenticator's own HTTP handlers on mux (e.g.
	// the login form submission). result is invoked with the authenticated
	// attributes when login completes.
	RegisterRoutes(mux *http.ServeMux, result Result)
	// Start begins the login for the given OpenID4VCI session, e.g. by rendering
	// a login page or redirecting to an external IdP.
	Start(w http.ResponseWriter, r *http.Request, session string) error
}
