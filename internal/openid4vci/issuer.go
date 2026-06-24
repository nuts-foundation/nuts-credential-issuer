// Package openid4vci implements the OpenID4VCI issuer surface: the metadata
// well-knowns, the authorization-code flow (/authorize, /token), and the
// /credential endpoint with credential-request proof validation. Authentication
// is delegated to a swappable auth.Authenticator and minting to a Nuts node.
package openid4vci

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
)

// ConsentPath is where the consent form submits. The login path is owned by the
// authenticator, which registers it on the mux itself.
const ConsentPath = "/consent"

// Renderer renders the issuer's HTML pages.
type Renderer interface {
	Consent(w http.ResponseWriter, data ConsentData) error
	Redirect(w http.ResponseWriter, data RedirectData) error
	Error(w http.ResponseWriter, status int, message string)
}

// ConsentData is the consent page model.
type ConsentData struct {
	SessionID      string
	PostPath       string
	OrgName        string
	OrgIdentifier  string
	CredentialType string
	// Recipient is the host of the wallet the credential will be issued to;
	// RecipientDetail is the path/identifier shown muted beneath it.
	Recipient       string
	RecipientDetail string
	// Services is the comma-separated default for the editable services field.
	Services string
}

// RedirectData is the auto-submit redirect page model: it returns the
// authorization code and state to the wallet's redirect_uri.
type RedirectData struct {
	Action string
	Code   string
	State  string
}

// Options configures an Issuer.
type Options struct {
	// BaseURL is the Credential Issuer Identifier and the base for the token,
	// credential and nonce endpoints (server-to-server URLs).
	BaseURL string
	// AuthorizationEndpoint is the URL advertised as authorization_endpoint (the
	// one browser-facing URL). Defaults to BaseURL + "/authorize".
	AuthorizationEndpoint string
	// IssuerSubject is the Nuts subject whose did:web the issuer issues from. Its
	// DID is resolved from the node at issuance time (and cached).
	IssuerSubject      string
	CredentialValidity time.Duration
	CredentialConfigID string
	Authenticator      auth.Authenticator
	Nuts               *nutsclient.Client
	Renderer           Renderer
	InsecureDIDWeb     bool
	// CallbackRewriteFrom/To rewrite the host of the wallet's callback URL only
	// when rendering the browser redirect (not for /token matching), so a browser
	// can reach a node whose NUTS_URL is an internal hostname.
	CallbackRewriteFrom string
	CallbackRewriteTo   string
	SessionTTL          time.Duration
	Now                 func() time.Time
	HTTPClient          *http.Client
}

// Issuer serves the OpenID4VCI issuer endpoints.
type Issuer struct {
	opts     Options
	configID string
	store    *sessionStore
	proofs   *proofValidator
	now      func() time.Time
	stop     chan struct{}

	didMu     sync.Mutex
	issuerDID string // cached resolution of opts.IssuerSubject
}

// New constructs an Issuer and starts its background session reaper.
func New(opts Options) (*Issuer, error) {
	if opts.BaseURL == "" || opts.IssuerSubject == "" {
		return nil, fmt.Errorf("BaseURL and IssuerSubject are required")
	}
	if opts.Authenticator == nil || opts.Nuts == nil || opts.Renderer == nil {
		return nil, fmt.Errorf("Authenticator, Nuts and Renderer are required")
	}
	if opts.AuthorizationEndpoint == "" {
		opts.AuthorizationEndpoint = opts.BaseURL + "/authorize"
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = 10 * time.Minute
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	configID := opts.CredentialConfigID
	if configID == "" {
		configID = credentials.ServiceProviderCredentialType
	}
	i := &Issuer{
		opts:     opts,
		configID: configID,
		store:    newSessionStore(opts.SessionTTL, now),
		proofs:   newProofValidator(opts.BaseURL, opts.InsecureDIDWeb, opts.HTTPClient, now),
		now:      now,
		stop:     make(chan struct{}),
	}
	go i.store.gc(i.stop)
	return i, nil
}

// Close stops the background session reaper.
func (i *Issuer) Close() { close(i.stop) }

// resolveIssuerDID resolves and caches the issuer's did:web from its configured
// Nuts subject. It is resolved lazily so the subject may be created (via Nuts
// Admin) after the issuer starts.
func (i *Issuer) resolveIssuerDID(ctx context.Context) (string, error) {
	i.didMu.Lock()
	defer i.didMu.Unlock()
	if i.issuerDID != "" {
		return i.issuerDID, nil
	}
	did, err := i.opts.Nuts.SubjectDID(ctx, i.opts.IssuerSubject)
	if err != nil {
		return "", err
	}
	i.issuerDID = did
	return did, nil
}

// Handler returns the HTTP handler exposing all issuer endpoints. The
// authenticator registers its own routes (e.g. the login submission) on the
// same mux.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", i.handleIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", i.handleASMetadata)
	mux.HandleFunc("GET /authorize", i.handleAuthorize)
	mux.HandleFunc("POST "+ConsentPath, i.handleConsent)
	mux.HandleFunc("POST /token", i.handleToken)
	mux.HandleFunc("POST /nonce", i.handleNonce)
	mux.HandleFunc("POST /credential", i.handleCredential)
	i.opts.Authenticator.RegisterRoutes(mux, i.onAuthenticated)
	return mux
}

func (i *Issuer) handleIssuerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, issuerMetadata(i.opts.BaseURL, i.configID))
}

func (i *Issuer) handleASMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authServerMetadata(i.opts.BaseURL, i.opts.AuthorizationEndpoint))
}

func (i *Issuer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		oauthErr(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be code")
		return
	}
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	if redirectURI == "" || state == "" || challenge == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "redirect_uri, state and code_challenge are required")
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}
	configID, err := credentialConfigFromAuthDetails(q.Get("authorization_details"), i.configID)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	recipientHost, recipientDetail := parseRecipient(q.Get("client_id"))
	sess := &session{
		redirectURI:     redirectURI,
		state:           state,
		codeChallenge:   challenge,
		configID:        configID,
		recipientHost:   recipientHost,
		recipientDetail: recipientDetail,
	}
	i.store.create(sess)

	if err := i.opts.Authenticator.Start(w, r, sess.id); err != nil {
		i.opts.Renderer.Error(w, http.StatusInternalServerError, "kan authenticatie niet starten")
	}
}

// onAuthenticated is the auth.Result continuation: once the authenticator has
// authenticated the user it hands back the attributes, which we bind to the
// session and follow with the consent page.
func (i *Issuer) onAuthenticated(w http.ResponseWriter, _ *http.Request, sessionID string, attrs auth.Attributes) {
	sess, ok := i.store.get(sessionID)
	if !ok {
		i.opts.Renderer.Error(w, http.StatusBadRequest, "onbekende of verlopen sessie")
		return
	}
	sess.attrs = &attrs
	if err := i.opts.Renderer.Consent(w, ConsentData{
		SessionID:       sess.id,
		PostPath:        ConsentPath,
		OrgName:         attrs.LegalName,
		OrgIdentifier:   attrs.Identifier,
		CredentialType:  sess.configID,
		Recipient:       sess.recipientHost,
		RecipientDetail: sess.recipientDetail,
		Services:        strings.Join(credentials.DefaultServiceProviderServices, ", "),
	}); err != nil {
		i.opts.Renderer.Error(w, http.StatusInternalServerError, "kan toestemmingsscherm niet tonen")
	}
}

func (i *Issuer) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		i.opts.Renderer.Error(w, http.StatusBadRequest, "ongeldig formulier")
		return
	}
	sess, ok := i.store.get(r.FormValue("session"))
	if !ok {
		i.opts.Renderer.Error(w, http.StatusBadRequest, "onbekende of verlopen sessie")
		return
	}
	if sess.attrs == nil {
		i.opts.Renderer.Error(w, http.StatusBadRequest, "sessie is niet geauthenticeerd")
		return
	}
	sess.services = splitServices(r.FormValue("services"))
	code := i.store.bindCode(sess)
	// Keep the original redirect_uri for the /token check; only the browser-facing
	// action may be rewritten to a host the browser can resolve.
	action := sess.redirectURI
	if i.opts.CallbackRewriteFrom != "" {
		action = strings.ReplaceAll(action, i.opts.CallbackRewriteFrom, i.opts.CallbackRewriteTo)
	}
	if err := i.opts.Renderer.Redirect(w, RedirectData{
		Action: action,
		Code:   code,
		State:  sess.state,
	}); err != nil {
		i.opts.Renderer.Error(w, http.StatusInternalServerError, "kan doorverwijzing niet tonen")
	}
}

func (i *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	sess, ok := i.store.takeByCode(r.Form.Get("code"))
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

	token := i.store.bindToken(sess)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(i.opts.SessionTTL.Seconds()),
		"c_nonce":      i.store.issueNonce(),
	})
}

func (i *Issuer) handleNonce(w http.ResponseWriter, _ *http.Request) {
	// The Nonce Endpoint is not cacheable (OpenID4VCI 1.0 §7).
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": i.store.issueNonce()})
}

func (i *Issuer) handleCredential(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		oauthErr(w, http.StatusUnauthorized, "invalid_token", "missing bearer access token")
		return
	}
	sess, ok := i.store.getByToken(token)
	if !ok || sess.attrs == nil {
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

	holderDID, err := i.proofs.validate(r.Context(), proofJWT, i.store.consumeNonce)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_proof", err.Error())
		return
	}

	issuerDID, err := i.resolveIssuerDID(r.Context())
	if err != nil {
		slog.Error("could not resolve issuer DID", "subject", i.opts.IssuerSubject, "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "issuer is not provisioned")
		return
	}

	issueReq := credentials.BuildServiceProviderCredential(
		issuerDID,
		credentials.ServiceProvider{DID: holderDID, LegalName: sess.attrs.LegalName, Services: sess.services},
		i.opts.CredentialValidity,
		i.now(),
	)
	vc, err := i.opts.Nuts.IssueVC(r.Context(), issueReq)
	if err != nil {
		slog.Error("credential minting failed", "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "failed to mint credential")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": []map[string]any{{"credential": vc}},
	})
}

// credentialRequest models the OpenID4VCI credential request. It accepts both
// the OpenID4VCI 1.0 plural "proofs" shape and the older singular "proof"
// shape, since which one the wallet sends is Nuts-node-version dependent.
type credentialRequest struct {
	Proof *struct {
		ProofType string `json:"proof_type"`
		JWT       string `json:"jwt"`
	} `json:"proof"`
	Proofs *struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
}

func (c credentialRequest) proofJWT() string {
	if c.Proofs != nil && len(c.Proofs.JWT) > 0 {
		return c.Proofs.JWT[0]
	}
	if c.Proof != nil {
		return c.Proof.JWT
	}
	return ""
}

// credentialConfigFromAuthDetails extracts the requested credential
// configuration id from the authorization_details parameter, defaulting to the
// issuer's only configuration when none is given. It rejects a request for a
// configuration this issuer does not offer.
func credentialConfigFromAuthDetails(raw, want string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return want, nil
	}
	var entries []struct {
		Type                      string `json:"type"`
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("invalid authorization_details: %w", err)
	}
	for _, e := range entries {
		if e.Type != "openid_credential" {
			continue
		}
		if e.CredentialConfigurationID == "" || e.CredentialConfigurationID == want {
			return want, nil
		}
		return "", fmt.Errorf("unsupported credential_configuration_id %q", e.CredentialConfigurationID)
	}
	return want, nil
}

// parseRecipient derives a human-readable label for the recipient wallet from
// its OAuth client_id, split into a prominent host and a muted detail (the path
// or DID identifier, often a GUID). Nuts uses an entity_id client_id (e.g.
// "http://host/oauth2/subject"); it also handles a did:web client_id.
func parseRecipient(clientID string) (host, detail string) {
	if clientID == "" {
		return "", ""
	}
	if rest, ok := strings.CutPrefix(clientID, "did:web:"); ok {
		parts := strings.Split(rest, ":")
		if h, err := url.PathUnescape(parts[0]); err == nil {
			host = h
		} else {
			host = parts[0]
		}
		if len(parts) > 1 {
			detail = strings.Join(parts[1:], "/")
		}
		return host, detail
	}
	if u, err := url.Parse(clientID); err == nil && u.Host != "" {
		return u.Host, strings.TrimPrefix(u.Path, "/")
	}
	return clientID, ""
}

// splitServices parses the comma-separated services field from the consent form.
func splitServices(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(s); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func oauthErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
