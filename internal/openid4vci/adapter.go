// Package openid4vci is the inbound HTTP adapter for the OpenID4VCI issuer
// surface. It maps the OpenID4VCI/OAuth wire protocol (metadata, /authorize,
// /token, /nonce, /credential) onto the application service, and renders pages
// via a Presenter. It holds no business logic or state.
package openid4vci

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
)

// Options configures the adapter.
type Options struct {
	// BaseURL is the Credential Issuer Identifier and the base for the token,
	// credential and nonce endpoints (server-to-server URLs).
	BaseURL string
	// AuthorizationEndpoint is the URL advertised as authorization_endpoint (the
	// one browser-facing URL).
	AuthorizationEndpoint string
	Service               *issuer.Service
	Presenter             issuer.Presenter
	Authenticator         auth.Authenticator
	// CallbackRewriteFrom/To rewrite the host of the wallet's callback URL only
	// when rendering the browser redirect, so a browser can reach a node whose
	// NUTS_URL is an internal hostname.
	CallbackRewriteFrom string
	CallbackRewriteTo   string
}

// Adapter serves the OpenID4VCI HTTP endpoints.
type Adapter struct {
	opts     Options
	configID string
}

// New constructs the adapter.
func New(opts Options) (*Adapter, error) {
	if opts.BaseURL == "" {
		return nil, errors.New("BaseURL is required")
	}
	if opts.Service == nil || opts.Presenter == nil || opts.Authenticator == nil {
		return nil, errors.New("Service, Presenter and Authenticator are required")
	}
	if opts.AuthorizationEndpoint == "" {
		opts.AuthorizationEndpoint = opts.BaseURL + "/authorize"
	}
	return &Adapter{opts: opts, configID: opts.Service.CredentialType()}, nil
}

// Handler returns the HTTP handler exposing all issuer endpoints.
func (a *Adapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", a.handleIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleASMetadata)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST "+issuer.ConsentPath, a.handleConsent)
	mux.HandleFunc("POST /token", a.handleToken)
	mux.HandleFunc("POST /nonce", a.handleNonce)
	mux.HandleFunc("POST /credential", a.handleCredential)
	a.opts.Authenticator.RegisterRoutes(mux, a.onAuthenticated)
	return mux
}

func (a *Adapter) handleIssuerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, issuerMetadata(a.opts.BaseURL, a.configID))
}

func (a *Adapter) handleASMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authServerMetadata(a.opts.BaseURL, a.opts.AuthorizationEndpoint))
}

func (a *Adapter) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		oauthErr(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be code")
		return
	}
	if q.Get("redirect_uri") == "" || q.Get("state") == "" || q.Get("code_challenge") == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "redirect_uri, state and code_challenge are required")
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}
	requested, err := requestedConfigID(q.Get("authorization_details"))
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	host, detail := parseRecipient(q.Get("client_id"))

	id, err := a.opts.Service.StartAuthorization(issuer.AuthorizeParams{
		RedirectURI:       q.Get("redirect_uri"),
		OAuthState:        q.Get("state"),
		CodeChallenge:     q.Get("code_challenge"),
		RequestedConfigID: requested,
		Recipient:         issuance.Recipient{Host: host, Detail: detail},
	})
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := a.opts.Authenticator.Start(w, r, id); err != nil {
		a.opts.Presenter.Error(w, http.StatusInternalServerError, "kan authenticatie niet starten")
	}
}

// onAuthenticated is the auth.Result continuation invoked once the user is
// authenticated; it advances the issuance and renders consent.
func (a *Adapter) onAuthenticated(w http.ResponseWriter, _ *http.Request, sessionID string, attrs auth.Attributes) {
	view, err := a.opts.Service.Authenticate(sessionID, issuance.Organization{
		LegalName:  attrs.LegalName,
		Identifier: attrs.Identifier,
	})
	if err != nil {
		a.renderServiceError(w, err)
		return
	}
	if err := a.opts.Presenter.Consent(w, view); err != nil {
		a.opts.Presenter.Error(w, http.StatusInternalServerError, "kan toestemmingsscherm niet tonen")
	}
}

func (a *Adapter) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.opts.Presenter.Error(w, http.StatusBadRequest, "ongeldig formulier")
		return
	}
	view, err := a.opts.Service.Consent(r.FormValue("session"), splitServices(r.FormValue("services")))
	if err != nil {
		a.renderServiceError(w, err)
		return
	}
	// Keep the original redirect_uri for the /token check; only rewrite the
	// browser-facing action to a host the browser can resolve.
	if a.opts.CallbackRewriteFrom != "" {
		view.Action = strings.ReplaceAll(view.Action, a.opts.CallbackRewriteFrom, a.opts.CallbackRewriteTo)
	}
	if err := a.opts.Presenter.Redirect(w, view); err != nil {
		a.opts.Presenter.Error(w, http.StatusInternalServerError, "kan doorverwijzing niet tonen")
	}
}

func (a *Adapter) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	res, err := a.opts.Service.ExchangeToken(r.Form.Get("code"), r.Form.Get("code_verifier"), r.Form.Get("redirect_uri"))
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": res.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   res.ExpiresIn,
		"c_nonce":      res.CNonce,
	})
}

func (a *Adapter) handleNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store") // OpenID4VCI 1.0 §7
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": a.opts.Service.IssueNonce()})
}

func (a *Adapter) handleCredential(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		oauthErr(w, http.StatusUnauthorized, "invalid_token", "missing bearer access token")
		return
	}
	var req credentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "malformed credential request")
		return
	}
	proofJWT := req.proofJWT()
	if proofJWT == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_proof", "credential request is missing a jwt proof")
		return
	}

	vc, err := a.opts.Service.IssueCredential(r.Context(), token, proofJWT)
	switch {
	case errors.Is(err, issuer.ErrInvalidToken):
		oauthErr(w, http.StatusUnauthorized, "invalid_token", "unknown or expired access token")
		return
	case errors.Is(err, issuer.ErrInvalidProof):
		oauthErr(w, http.StatusBadRequest, "invalid_proof", err.Error())
		return
	case err != nil:
		slog.Error("credential issuance failed", "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "failed to mint credential")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": []map[string]any{{"credential": vc}},
	})
}

// renderServiceError maps an application error to the HTML error page.
func (a *Adapter) renderServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, issuer.ErrSessionNotFound):
		a.opts.Presenter.Error(w, http.StatusBadRequest, "onbekende of verlopen sessie")
	case errors.Is(err, issuance.ErrInvalidState):
		a.opts.Presenter.Error(w, http.StatusBadRequest, "ongeldige stap in de sessie")
	default:
		a.opts.Presenter.Error(w, http.StatusInternalServerError, "er is iets misgegaan")
	}
}
