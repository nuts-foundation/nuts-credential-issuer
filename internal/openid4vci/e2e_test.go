package openid4vci_test

// This test drives the full external OpenID4VCI flow against a real Nuts holder
// node and asserts a ServiceProviderCredential lands in the wallet. It is
// skipped unless the environment below is set, because it needs a running Nuts
// node that can reach this test's in-process issuer.
//
// Required environment:
//
//	E2E_NUTS_INTERNAL_URL   Nuts node internal API base, e.g. http://localhost:8081
//	E2E_NUTS_SUBJECT        the holder subject id on the node (created via /internal/vdr/v2/subject)
//	E2E_WALLET_DID          the holder's did:web (the credential subject)
//	E2E_ISSUER_LISTEN_ADDR  address this test's issuer binds to, e.g. :18090
//	E2E_ISSUER_BASE_URL     base URL the NODE can reach the issuer at, e.g. http://host.docker.internal:18090
//	E2E_ISSUER_SUBJECT      the Nuts subject the issuer issues from (default "issuer")
//
// Example (node from nuts-lsp-demo, issuer DID provisioned on the same node):
//
//	E2E_NUTS_INTERNAL_URL=http://localhost:18081 \
//	E2E_NUTS_SUBJECT=sp1 E2E_WALLET_DID=did:web:localhost%3A18080:iam:sp1 \
//	E2E_ISSUER_LISTEN_ADDR=:18090 E2E_ISSUER_BASE_URL=http://host.docker.internal:18090 \
//	E2E_ISSUER_SUBJECT=issuer \
//	go test ./internal/openid4vci/ -run TestE2E -v

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth/eherkenning"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/didweb"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/memory"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

func TestE2E_IssueServiceProviderCredential(t *testing.T) {
	nodeInternal := os.Getenv("E2E_NUTS_INTERNAL_URL")
	subject := os.Getenv("E2E_NUTS_SUBJECT")
	walletDID := os.Getenv("E2E_WALLET_DID")
	listenAddr := os.Getenv("E2E_ISSUER_LISTEN_ADDR")
	issuerBaseURL := os.Getenv("E2E_ISSUER_BASE_URL")
	issuerSubject := os.Getenv("E2E_ISSUER_SUBJECT")
	if issuerSubject == "" {
		issuerSubject = "issuer"
	}
	if nodeInternal == "" || subject == "" || walletDID == "" || listenAddr == "" || issuerBaseURL == "" {
		t.Skip("E2E_* environment not set; skipping end-to-end test")
	}

	renderer, err := web.New("Nuts Credential Issuer")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := eherkenning.New("Voorbeeld Dienstverlener B.V.", "90000001", "Nuts Credential Issuer")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimRight(issuerBaseURL, "/")
	nuts := nutsclient.New(strings.TrimRight(nodeInternal, "/"), nil)
	store := memory.NewStore(10*time.Minute, time.Now)
	defer store.Close()
	verifier := proof.NewVerifier(didweb.New(true, nil), base, time.Now)
	svc := issuer.NewService(store, nuts, nuts, verifier, time.Now, issuer.Config{
		IssuerSubject:      issuerSubject,
		ConfigID:           credentials.ServiceProviderCredentialType,
		CredentialValidity: 24 * time.Hour,
		AccessTokenTTL:     10 * time.Minute,
	})
	adapter, err := openid4vci.New(openid4vci.Options{
		BaseURL:       base,
		Service:       svc,
		Presenter:     renderer,
		Authenticator: authenticator,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Addr: listenAddr, Handler: adapter.Handler()}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(200 * time.Millisecond) // let the listener come up

	// 1. Ask the node (wallet) to start the OpenID4VCI flow against our issuer.
	reqBody, _ := json.Marshal(map[string]any{
		"wallet_did": walletDID,
		"issuer":     strings.TrimRight(issuerBaseURL, "/"),
		"authorization_details": []map[string]any{
			{"type": "openid_credential", "credential_configuration_id": "ServiceProviderCredential"},
		},
		"redirect_uri": "http://localhost/done",
	})
	startResp := postJSON(t, nodeInternal+"/internal/auth/v2/"+subject+"/request-credential", reqBody)
	var start struct {
		RedirectURI string `json:"redirect_uri"`
		SessionID   string `json:"session_id"`
	}
	if err := json.Unmarshal(startResp, &start); err != nil {
		t.Fatalf("parse request-credential response: %v (%s)", err, startResp)
	}
	if start.RedirectURI == "" {
		t.Fatalf("node did not return a redirect_uri: %s", startResp)
	}

	// 2. Act as the browser: log in, consent, and follow the redirect back to
	// the node's callback so it can finish the token + credential exchange.
	client := &http.Client{
		// Do not follow the final redirect into the node automatically; we call
		// the callback explicitly below.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       30 * time.Second,
	}

	loginHTML := httpGet(t, client, start.RedirectURI)
	sessionID := firstSubmatch(t, `name="session"\s+value="([^"]+)"`, loginHTML, "session id on login page")
	consentHTML := httpPostForm(t, client, issuerBaseURL+eherkenning.LoginPath, url.Values{"session": {sessionID}})
	_ = consentHTML
	redirectHTML := httpPostForm(t, client, issuerBaseURL+issuer.ConsentPath, url.Values{"session": {sessionID}})

	action := firstSubmatch(t, `action="([^"]+)"`, redirectHTML, "redirect action")
	code := firstSubmatch(t, `name="code"\s+value="([^"]+)"`, redirectHTML, "code")
	state := firstSubmatch(t, `name="state"\s+value="([^"]+)"`, redirectHTML, "state")

	callbackURL := action + "?" + url.Values{"code": {code}, "state": {state}}.Encode()
	resp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("node callback: %v", err)
	}
	resp.Body.Close()

	// 3. The node should now hold a ServiceProviderCredential for the wallet DID.
	if !walletHoldsCredential(t, nodeInternal, subject, walletDID) {
		t.Fatal("ServiceProviderCredential was not found in the wallet")
	}
}

func walletHoldsCredential(t *testing.T, nodeInternal, subject, walletDID string) bool {
	t.Helper()
	// Give the node a moment to store the credential.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(nodeInternal + "/internal/vcr/v2/holder/" + subject + "/vc")
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "ServiceProviderCredential") && strings.Contains(string(body), walletDID) {
				return true
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	return false
}

func postJSON(t *testing.T, url string, body []byte) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s = %d: %s", url, resp.StatusCode, out)
	}
	return out
}

func httpGet(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

func httpPostForm(t *testing.T, c *http.Client, url string, form url.Values) string {
	t.Helper()
	resp, err := c.PostForm(url, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

func firstSubmatch(t *testing.T, pattern, s, what string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) < 2 {
		t.Fatalf("could not find %s in page:\n%s", what, s)
	}
	return m[1]
}
