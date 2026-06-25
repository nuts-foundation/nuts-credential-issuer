package openid4vci_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

const (
	testAudience  = "https://issuer.example.nl"
	testIssuerDID = "did:web:issuer.example.nl"
	testHolderDID = "did:web:holder.example.nl"
)

// --- stubs ------------------------------------------------------------------

type stubAuth struct {
	attrs  auth.Attributes
	result auth.Result
}

func (a *stubAuth) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "login")
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		a.result(w, r, a.attrs)
	})
}

type stubRenderer struct{ lastRedirect web.RedirectView }

func (r *stubRenderer) Consent(http.ResponseWriter, web.ConsentView) error { return nil }
func (r *stubRenderer) Redirect(w http.ResponseWriter, v web.RedirectView) error {
	r.lastRedirect = v
	_, _ = io.WriteString(w, v.Code)
	return nil
}
func (r *stubRenderer) Error(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}

// stubVerifier echoes the proof string as the nonce, so flow tests can drive the
// nonce check without real crypto (proof crypto is tested in package proof).
type stubVerifier struct {
	holderDID string
	err       error
}

func (v stubVerifier) Verify(_ context.Context, token string) (proof.Result, error) {
	if v.err != nil {
		return proof.Result{}, v.err
	}
	return proof.Result{HolderDID: v.holderDID, Nonce: token}, nil
}

type issuedVC struct {
	Type              []string       `json:"type"`
	Issuer            string         `json:"issuer"`
	CredentialSubject map[string]any `json:"credentialSubject"`
	Format            string         `json:"format"`
}

type fakeNode struct {
	server   *httptest.Server
	lastBody issuedVC
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	n := &fakeNode{}
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/vdr/v2/subject/issuer", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]string{testIssuerDID})
	})
	mux.HandleFunc("/internal/vcr/v2/issuer/vc", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&n.lastBody)
		_ = json.NewEncoder(w).Encode("header.payload.signature")
	})
	n.server = httptest.NewServer(mux)
	t.Cleanup(n.server.Close)
	return n
}

// --- harness ----------------------------------------------------------------

type harness struct {
	srv      *httptest.Server
	node     *fakeNode
	renderer *stubRenderer
}

func newHarness(t *testing.T, opts openid4vci.Options, verr error) *harness {
	t.Helper()
	now := time.Now()
	node := newFakeNode(t)
	nuts := nutsclient.New(node.server.URL, nil)
	svc := issuer.NewService(nuts, nuts, func() time.Time { return now },
		issuer.Config{IssuerSubject: "issuer"})

	renderer := &stubRenderer{}
	if opts.BaseURL == "" {
		opts.BaseURL = testAudience
	}
	opts.Service = svc
	opts.Renderer = renderer
	opts.Proofs = stubVerifier{holderDID: testHolderDID, err: verr}
	opts.LoginPath = "/login"
	opts.Now = func() time.Time { return now }
	adapter, err := openid4vci.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	authn := &stubAuth{attrs: auth.Attributes{LegalName: "Voorbeeld B.V.", Identifier: "90000001"}, result: adapter.OnAuthenticated}

	mux := http.NewServeMux()
	adapter.RegisterRoutes(mux)
	authn.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// A cookie jar carries the session cookie through the login/consent steps.
	jar, _ := cookiejar.New(nil)
	srv.Client().Jar = jar
	return &harness{srv: srv, node: node, renderer: renderer}
}

// driveToToken runs authorize -> login -> consent -> token and returns the
// access token and c_nonce.
func (h *harness) driveToToken(t *testing.T, redirectURI, services string) (token, cNonce string) {
	t.Helper()
	c := h.srv.Client()
	verifier := "test-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := h.srv.URL + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {"st"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		// client_id host must match the holder DID host (consent/proof binding).
		"client_id": {"http://holder.example.nl/oauth2/wallet"},
	}.Encode()
	mustGet(t, c, authURL) // follows the 302 to /login, setting the session cookie
	mustPostForm(t, c, h.srv.URL+"/login", url.Values{})
	code := string(mustPostForm(t, c, h.srv.URL+"/consent", url.Values{"services": {services}}))

	body := mustPostForm(t, c, h.srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
	var tok struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatal(err)
	}
	return tok.AccessToken, tok.CNonce
}

// --- tests ------------------------------------------------------------------

func TestFlow_HappyPath(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, nil)
	token, cNonce := h.driveToToken(t, "http://wallet/cb", "gbc-client, gbc-server")
	if token == "" || cNonce == "" {
		t.Fatal("missing token or c_nonce")
	}

	body := mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", token,
		`{"proofs":{"jwt":["`+cNonce+`"]}}`, http.StatusOK)
	var cred struct {
		Credentials []struct {
			Credential json.RawMessage `json:"credential"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(body, &cred); err != nil {
		t.Fatal(err)
	}
	if len(cred.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(cred.Credentials))
	}

	subj := h.node.lastBody.CredentialSubject
	if subj["id"] != testHolderDID {
		t.Errorf("subject id = %v, want holder DID", subj["id"])
	}
	if subj["name"] != "Voorbeeld B.V." {
		t.Errorf("subject name = %v", subj["name"])
	}
	if h.node.lastBody.Issuer != testIssuerDID {
		t.Errorf("issuer = %v, want resolved DID", h.node.lastBody.Issuer)
	}
	if h.node.lastBody.Format != "jwt_vc" {
		t.Errorf("format = %v", h.node.lastBody.Format)
	}
	svcs, _ := subj["services"].([]any)
	if len(svcs) != 2 || svcs[0] != "gbc-client" || svcs[1] != "gbc-server" {
		t.Errorf("services = %v, want [gbc-client gbc-server]", subj["services"])
	}
}

func TestCredential_RejectsUnauthenticated(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, nil)
	mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", "", `{"proofs":{"jwt":["x"]}}`, http.StatusUnauthorized)
	mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", "nope", `{"proofs":{"jwt":["x"]}}`, http.StatusUnauthorized)
}

func TestCredential_RejectsMissingProof(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, nil)
	token, _ := h.driveToToken(t, "http://wallet/cb", "")
	mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", token, `{}`, http.StatusBadRequest)
}

func TestCredential_RejectsBadNonce(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, nil)
	token, _ := h.driveToToken(t, "http://wallet/cb", "")
	mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", token, `{"proofs":{"jwt":["never-issued"]}}`, http.StatusBadRequest)
	if h.node.lastBody.Issuer != "" {
		t.Error("node was called despite a bad nonce")
	}
}

func TestCredential_RejectsInvalidProof(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, context.DeadlineExceeded) // verifier fails
	token, cNonce := h.driveToToken(t, "http://wallet/cb", "")
	mustCredential(t, h.srv.Client(), h.srv.URL+"/credential", token, `{"proofs":{"jwt":["`+cNonce+`"]}}`, http.StatusBadRequest)
}

func TestMetadata(t *testing.T) {
	h := newHarness(t, openid4vci.Options{}, nil)
	var im map[string]any
	_ = json.Unmarshal(mustGet(t, h.srv.Client(), h.srv.URL+"/.well-known/openid-credential-issuer"), &im)
	if im["credential_issuer"] != testAudience || im["credential_endpoint"] != testAudience+"/credential" {
		t.Errorf("issuer metadata = %v", im)
	}
	configs, _ := im["credential_configurations_supported"].(map[string]any)
	if _, ok := configs["ServiceProviderCredential"]; !ok {
		t.Errorf("metadata missing ServiceProviderCredential: %v", configs)
	}
	var as map[string]any
	_ = json.Unmarshal(mustGet(t, h.srv.Client(), h.srv.URL+"/.well-known/oauth-authorization-server"), &as)
	if as["token_endpoint"] != testAudience+"/token" || as["authorization_endpoint"] != testAudience+"/authorize" {
		t.Errorf("AS metadata = %v", as)
	}
}

// --- helpers ----------------------------------------------------------------

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
