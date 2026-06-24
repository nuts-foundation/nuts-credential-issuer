package openid4vci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
)

type stubRenderer struct{ lastRedirect RedirectData }

func (s *stubRenderer) Consent(http.ResponseWriter, ConsentData) error { return nil }
func (s *stubRenderer) Redirect(w http.ResponseWriter, data RedirectData) error {
	s.lastRedirect = data
	_, _ = io.WriteString(w, data.Code)
	return nil
}
func (s *stubRenderer) Error(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}

const stubLoginPath = "/login"
const testIssuerDID = "did:web:issuer.example.nl"

type stubAuth struct{ attrs auth.Attributes }

func (a stubAuth) Start(w http.ResponseWriter, _ *http.Request, session string) error {
	_, _ = io.WriteString(w, session)
	return nil
}
func (a stubAuth) RegisterRoutes(mux *http.ServeMux, result auth.Result) {
	mux.HandleFunc("POST "+stubLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		result(w, r, r.FormValue("session"), a.attrs)
	})
}

// fakeNode is a stand-in for the Nuts node issuer API. It records the last
// issue request and returns a fixed jwt_vc (a JSON-encoded string).
type fakeNode struct {
	server   *httptest.Server
	lastBody nutsclient.IssueVCRequest
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	n := &fakeNode{}
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/vdr/v2/subject/issuer", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{testIssuerDID})
	})
	mux.HandleFunc("/internal/vcr/v2/issuer/vc", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&n.lastBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode("header.payload.signature") // jwt_vc as a JSON string
	})
	n.server = httptest.NewServer(mux)
	t.Cleanup(n.server.Close)
	return n
}

func newTestIssuer(t *testing.T, node *fakeNode, now time.Time) (*Issuer, *stubRenderer) {
	t.Helper()
	renderer := &stubRenderer{}
	issuer, err := New(Options{
		BaseURL:            testAudience,
		IssuerSubject:      "issuer",
		CredentialValidity: 24 * time.Hour,
		Authenticator:      stubAuth{attrs: auth.Attributes{LegalName: "Voorbeeld B.V.", Identifier: "90000001"}},
		Nuts:               nutsclient.New(node.server.URL, nil),
		Renderer:           renderer,
		InsecureDIDWeb:     true,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	return issuer, renderer
}

func TestFlow_HappyPath(t *testing.T) {
	now := time.Now()
	node := newFakeNode(t)
	issuer, _ := newTestIssuer(t, node, now)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)
	holder := newHolder(t)

	client := srv.Client()
	verifier := "test-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := "http://wallet.example/callback"

	// 1. /authorize → stub authenticator writes the session id.
	authURL := srv.URL + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {"state-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"ServiceProviderCredential"}]`},
	}.Encode()
	sessionID := string(mustGet(t, client, authURL))
	if sessionID == "" {
		t.Fatal("no session id returned from /authorize")
	}

	// 2. /login → consent.
	mustPostForm(t, client, srv.URL+stubLoginPath, url.Values{"session": {sessionID}})

	// 3. /consent → authorization code (stub renderer writes it to the body).
	code := string(mustPostForm(t, client, srv.URL+ConsentPath, url.Values{"session": {sessionID}}))
	if code == "" {
		t.Fatal("no authorization code returned from /consent")
	}

	// 4. /token → access token + c_nonce.
	tokenBody := mustPostForm(t, client, srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
	var token struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
	}
	if err := json.Unmarshal(tokenBody, &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.CNonce == "" {
		t.Fatalf("token response missing access_token or c_nonce: %s", tokenBody)
	}

	// 5. /credential with a proof bound to the c_nonce.
	proof := holder.proof(t, testAudience, token.CNonce, now)
	credBody := mustCredential(t, client, srv.URL+"/credential", token.AccessToken,
		`{"proofs":{"jwt":["`+proof+`"]}}`, http.StatusOK)

	var cred struct {
		Credentials []struct {
			Credential json.RawMessage `json:"credential"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(credBody, &cred); err != nil {
		t.Fatal(err)
	}
	if len(cred.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(cred.Credentials))
	}
	var vc string
	_ = json.Unmarshal(cred.Credentials[0].Credential, &vc)
	if vc != "header.payload.signature" {
		t.Errorf("credential = %q, want the minted jwt_vc", vc)
	}

	// The issuer must have asked the node to mint with the holder DID as subject.
	subj, _ := node.lastBody.CredentialSubject.(map[string]any)
	if subj["id"] != holder.did {
		t.Errorf("credentialSubject.id = %v, want %q", subj["id"], holder.did)
	}
	if subj["name"] != "Voorbeeld B.V." {
		t.Errorf("credentialSubject.name = %v, want the authenticated legal name", subj["name"])
	}
	if node.lastBody.Format != "jwt_vc" {
		t.Errorf("format = %q, want jwt_vc", node.lastBody.Format)
	}
	if node.lastBody.Issuer != testIssuerDID {
		t.Errorf("issuer = %q, want the DID resolved from the subject", node.lastBody.Issuer)
	}
}

func TestCredential_RejectsUnauthenticated(t *testing.T) {
	now := time.Now()
	issuer, _ := newTestIssuer(t, newFakeNode(t), now)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)

	// No bearer token at all.
	mustCredential(t, srv.Client(), srv.URL+"/credential", "", `{"proofs":{"jwt":["x"]}}`, http.StatusUnauthorized)
	// Bogus bearer token.
	mustCredential(t, srv.Client(), srv.URL+"/credential", "nope", `{"proofs":{"jwt":["x"]}}`, http.StatusUnauthorized)
}

func TestCredential_RejectsMissingProof(t *testing.T) {
	now := time.Now()
	node := newFakeNode(t)
	issuer, _ := newTestIssuer(t, node, now)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)

	token := driveToToken(t, srv)
	mustCredential(t, srv.Client(), srv.URL+"/credential", token, `{}`, http.StatusBadRequest)
}

func TestCredential_RejectsInvalidProof(t *testing.T) {
	now := time.Now()
	node := newFakeNode(t)
	issuer, _ := newTestIssuer(t, node, now)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)

	token := driveToToken(t, srv)
	// A syntactically-bogus proof must be rejected, and nothing minted.
	mustCredential(t, srv.Client(), srv.URL+"/credential", token, `{"proofs":{"jwt":["not-a-jwt"]}}`, http.StatusBadRequest)
	if node.lastBody.Issuer != "" {
		t.Error("node was called despite an invalid proof")
	}
}

func TestMetadata(t *testing.T) {
	now := time.Now()
	issuer, _ := newTestIssuer(t, newFakeNode(t), now)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)

	var issuerMeta map[string]any
	_ = json.Unmarshal(mustGet(t, srv.Client(), srv.URL+"/.well-known/openid-credential-issuer"), &issuerMeta)
	if issuerMeta["credential_issuer"] != testAudience {
		t.Errorf("credential_issuer = %v", issuerMeta["credential_issuer"])
	}
	if issuerMeta["credential_endpoint"] != testAudience+"/credential" {
		t.Errorf("credential_endpoint = %v", issuerMeta["credential_endpoint"])
	}
	configs, _ := issuerMeta["credential_configurations_supported"].(map[string]any)
	if _, ok := configs["ServiceProviderCredential"]; !ok {
		t.Errorf("metadata does not advertise ServiceProviderCredential: %v", configs)
	}

	var asMeta map[string]any
	_ = json.Unmarshal(mustGet(t, srv.Client(), srv.URL+"/.well-known/oauth-authorization-server"), &asMeta)
	if asMeta["token_endpoint"] != testAudience+"/token" {
		t.Errorf("token_endpoint = %v", asMeta["token_endpoint"])
	}
	if asMeta["authorization_endpoint"] != testAudience+"/authorize" {
		t.Errorf("authorization_endpoint = %v", asMeta["authorization_endpoint"])
	}
}

func TestCallbackRewrite(t *testing.T) {
	now := time.Now()
	node := newFakeNode(t)
	renderer := &stubRenderer{}
	issuer, err := New(Options{
		BaseURL:             testAudience,
		IssuerSubject:       "issuer",
		CredentialValidity:  time.Hour,
		Authenticator:       stubAuth{attrs: auth.Attributes{LegalName: "X", Identifier: "1"}},
		Nuts:                nutsclient.New(node.server.URL, nil),
		Renderer:            renderer,
		CallbackRewriteFrom: "internal.host:8080",
		CallbackRewriteTo:   "localhost:8080",
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	srv := httptest.NewServer(issuer.Handler())
	t.Cleanup(srv.Close)
	client := srv.Client()

	verifier := "callback-rewrite-verifier-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := "http://internal.host:8080/oauth2/wallet/callback"

	sessionID := string(mustGet(t, client, srv.URL+"/authorize?"+url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()))
	mustPostForm(t, client, srv.URL+stubLoginPath, url.Values{"session": {sessionID}})
	mustPostForm(t, client, srv.URL+ConsentPath, url.Values{"session": {sessionID}})

	// The browser-facing redirect host is rewritten...
	action := renderer.lastRedirect.Action
	if !strings.Contains(action, "localhost:8080") || strings.Contains(action, "internal.host") {
		t.Errorf("redirect action not rewritten for the browser: %q", action)
	}
	// ...but the original redirect_uri still validates at /token.
	tokenBody := mustPostForm(t, client, srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {renderer.lastRedirect.Code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
	if !strings.Contains(string(tokenBody), "access_token") {
		t.Errorf("token exchange with the original redirect_uri failed: %s", tokenBody)
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "abc123-verifier"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !verifyPKCE(verifier, challenge) {
		t.Error("valid PKCE pair rejected")
	}
	if verifyPKCE("wrong", challenge) {
		t.Error("invalid PKCE pair accepted")
	}
	if verifyPKCE("", challenge) || verifyPKCE(verifier, "") {
		t.Error("empty PKCE accepted")
	}
}

// driveToToken runs authorize→login→consent→token and returns the access token.
func driveToToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	client := srv.Client()
	verifier := "verifier-verifier-verifier-verifier-1234"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := "http://wallet.example/callback"

	authURL := srv.URL + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	sessionID := string(mustGet(t, client, authURL))
	mustPostForm(t, client, srv.URL+stubLoginPath, url.Values{"session": {sessionID}})
	code := string(mustPostForm(t, client, srv.URL+ConsentPath, url.Values{"session": {sessionID}}))
	tokenBody := mustPostForm(t, client, srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(tokenBody, &token)
	return token.AccessToken
}

func mustGet(t *testing.T, c *http.Client, url string) []byte {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	return body
}

func mustPostForm(t *testing.T, c *http.Client, url string, form url.Values) []byte {
	t.Helper()
	resp, err := c.PostForm(url, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", url, resp.StatusCode, body)
	}
	return body
}

func mustCredential(t *testing.T, c *http.Client, url, token, body string, wantStatus int) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s = %d (want %d): %s", url, resp.StatusCode, wantStatus, respBody)
	}
	return respBody
}
