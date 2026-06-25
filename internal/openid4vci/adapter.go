// Package openid4vci is the inbound HTTP adapter for the OpenID4VCI issuer. It
// owns the OAuth/OpenID4VCI protocol entirely — metadata, the authorization-code
// flow, PKCE, access tokens, c_nonces and credential-request proofs — and drives
// the application service for the business steps (authenticate, consent, issue).
package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

// Renderer renders the issuer's HTML pages.
type Renderer interface {
	Consent(w http.ResponseWriter, v web.ConsentView) error
	Redirect(w http.ResponseWriter, v web.RedirectView) error
	Error(w http.ResponseWriter, status int, message string)
}

// ProofVerifier verifies a credential-request proof.
type ProofVerifier interface {
	Verify(ctx context.Context, token string) (proof.Result, error)
}

// Options configures the adapter.
type Options struct {
	// BaseURL is the Credential Issuer Identifier and the base for the authorize,
	// token, credential and nonce endpoints.
	BaseURL  string
	Service  *issuer.Service
	Renderer Renderer
	Proofs   ProofVerifier
	// LoginPath is the authenticator's login route; the adapter redirects the user
	// there to begin authentication.
	LoginPath string
	// SessionTTL bounds in-flight sessions and c_nonces; reported as expires_in.
	SessionTTL time.Duration
	Now        func() time.Time
}

// sessionCookie carries the in-flight session id through the authentication and
// consent steps. It is HttpOnly; the Secure flag for strict (HTTPS) mode is a
// follow-up (the demo runs over plain HTTP). See issue #2.
const sessionCookie = "cis_session"

// Adapter serves the OpenID4VCI HTTP endpoints.
type Adapter struct {
	opts     Options
	configID string
	store    *sessionStore
}

// New constructs the adapter and starts its session reaper. Call Close to stop it.
func New(opts Options) (*Adapter, error) {
	if opts.BaseURL == "" {
		return nil, errors.New("BaseURL is required")
	}
	if opts.Service == nil || opts.Renderer == nil || opts.Proofs == nil {
		return nil, errors.New("Service, Renderer and Proofs are required")
	}
	if opts.LoginPath == "" {
		return nil, errors.New("LoginPath is required")
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = 10 * time.Minute
	}
	return &Adapter{
		opts:     opts,
		configID: opts.Service.CredentialType(),
		store:    newSessionStore(opts.SessionTTL, opts.Now),
	}, nil
}

// Close stops the background session reaper.
func (a *Adapter) Close() { a.store.close() }

// RegisterRoutes mounts the OpenID4VCI endpoints on mux. The authenticator
// mounts its own routes (login page + submission) on the same mux separately.
func (a *Adapter) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", a.handleIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleASMetadata)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST /consent", a.handleConsent)
	mux.HandleFunc("POST /token", a.handleToken)
	mux.HandleFunc("POST /nonce", a.handleNonce)
	mux.HandleFunc("POST /credential", a.handleCredential)
}

func (a *Adapter) handleIssuerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, issuerMetadata(a.opts.BaseURL, a.configID))
}

func (a *Adapter) handleASMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authServerMetadata(a.opts.BaseURL))
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

	iss, err := a.opts.Service.Start(issuer.StartParams{
		RequestedConfigID: requested,
		Recipient:         issuance.Recipient{Host: host, Detail: detail},
	})
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	a.store.create(&session{
		issuance:      iss,
		redirectURI:   q.Get("redirect_uri"),
		state:         q.Get("state"),
		codeChallenge: q.Get("code_challenge"),
	})

	// Bind the browser to the session via an HttpOnly cookie and hand off to the
	// authenticator's login route.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    iss.ID(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.opts.SessionTTL.Seconds()),
	})
	http.Redirect(w, r, a.opts.LoginPath, http.StatusFound)
}

// OnAuthenticated is the auth.Result callback: once the authenticator has
// authenticated the user it advances the issuance (found via the session cookie)
// and renders consent. Wire it into the authenticator at construction.
func (a *Adapter) OnAuthenticated(w http.ResponseWriter, r *http.Request, attrs auth.Attributes) {
	sess, ok := a.store.get(sessionFromCookie(r))
	if !ok {
		a.opts.Renderer.Error(w, http.StatusBadRequest, "onbekende of verlopen sessie")
		return
	}
	details, err := a.opts.Service.Authenticate(sess.issuance, issuance.Organization{
		LegalName:  attrs.LegalName,
		Identifier: attrs.Identifier,
	})
	if err != nil {
		a.renderServiceError(w, err)
		return
	}
	if err := a.opts.Renderer.Consent(w, web.ConsentView{
		PostPath:        "/consent",
		CredentialType:  details.CredentialType,
		OrgName:         details.Organization.LegalName,
		OrgIdentifier:   details.Organization.Identifier,
		Recipient:       details.Recipient.Host,
		RecipientDetail: details.Recipient.Detail,
		Services:        strings.Join(details.Services, ", "),
	}); err != nil {
		a.opts.Renderer.Error(w, http.StatusInternalServerError, "kan toestemmingsscherm niet tonen")
	}
}

func (a *Adapter) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.opts.Renderer.Error(w, http.StatusBadRequest, "ongeldig formulier")
		return
	}
	sess, ok := a.store.get(sessionFromCookie(r))
	if !ok {
		a.opts.Renderer.Error(w, http.StatusBadRequest, "onbekende of verlopen sessie")
		return
	}
	if err := a.opts.Service.Consent(sess.issuance, splitServices(r.FormValue("services"))); err != nil {
		a.renderServiceError(w, err)
		return
	}
	code := newID()
	sess.code = code
	a.store.bindCode(code, sess.id())

	if err := a.opts.Renderer.Redirect(w, web.RedirectView{Action: sess.redirectURI, Code: code, State: sess.state}); err != nil {
		a.opts.Renderer.Error(w, http.StatusInternalServerError, "kan doorverwijzing niet tonen")
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
	sess, ok := a.store.takeByCode(r.Form.Get("code"))
	if !ok {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}
	if sess.redirectURI != r.Form.Get("redirect_uri") {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(r.Form.Get("code_verifier"), sess.codeChallenge) {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	token := newID()
	sess.token = token
	a.store.bindToken(token, sess.id())
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(a.opts.SessionTTL.Seconds()),
		"c_nonce":      a.store.issueNonce(),
	})
}

func (a *Adapter) handleNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store") // OpenID4VCI 1.0 §7
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": a.store.issueNonce()})
}

func (a *Adapter) handleCredential(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		oauthErr(w, http.StatusUnauthorized, "invalid_token", "missing bearer access token")
		return
	}
	sess, ok := a.store.byTokenLookup(token)
	if !ok {
		oauthErr(w, http.StatusUnauthorized, "invalid_token", "unknown or expired access token")
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

	res, err := a.opts.Proofs.Verify(r.Context(), proofJWT)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_proof", err.Error())
		return
	}
	if !a.store.consumeNonce(res.Nonce) {
		oauthErr(w, http.StatusBadRequest, "invalid_proof", "nonce is missing, unknown or expired")
		return
	}

	// Bind the issued-to DID (from the proof) to the wallet the user consented to
	// (derived from client_id): they must share a host, so we never issue to a
	// different party than the one shown on the consent screen.
	if holderHost, _ := parseRecipient(res.HolderDID); holderHost != sess.issuance.Snapshot().Recipient.Host {
		oauthErr(w, http.StatusBadRequest, "invalid_proof", "credential subject does not match the authenticated client")
		return
	}

	vc, err := a.opts.Service.Issue(r.Context(), sess.issuance, res.HolderDID)
	if err != nil {
		slog.Error("credential issuance failed", "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "failed to mint credential")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": []map[string]any{{"credential": vc}},
	})
}

// renderServiceError maps an application/domain error to the HTML error page.
func (a *Adapter) renderServiceError(w http.ResponseWriter, err error) {
	if errors.Is(err, issuance.ErrInvalidState) {
		a.opts.Renderer.Error(w, http.StatusBadRequest, "ongeldige stap in de sessie")
		return
	}
	a.opts.Renderer.Error(w, http.StatusInternalServerError, "er is iets misgegaan")
}
