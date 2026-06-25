//go:build integration

// This integration test runs the full OpenID4VCI issuance flow against a real
// Nuts node started with testcontainers: it creates the issuer + wallet subjects,
// runs the in-process issuer, issues a ServiceProviderCredential and asserts it
// lands in the wallet. It needs Docker and binds host ports 8080 and 8081 (stop
// the local `make up` stack first). Run with:
//
//	go test -tags integration -run TestIntegration ./internal/openid4vci/ -timeout 300s -v
package openid4vci_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth/eherkenning"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/didweb"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

// nodeURL is the node's public identity inside and outside the container. The
// port must equal the container's internal public port (8080) so that did:web
// (did:web:localhost%3A8080:...) resolves both inside the node and from the
// host-side issuer, which reaches the node via the published port.
const (
	nodeURL          = "http://localhost:8080"
	nodeInternalURL  = "http://localhost:8081"
	nodePublicPort   = "8080"
	nodeInternalPort = "8081"
)

func TestIntegration_IssueServiceProviderCredential(t *testing.T) {
	ctx := context.Background()
	startNode(t, ctx)

	createSubject(t, "issuer")
	createSubject(t, "wallet")
	walletDID := resolveDID(t, "wallet")

	// The node reaches the in-process issuer via host.docker.internal, which on
	// Linux is the docker bridge gateway, so bind all interfaces (not just loopback).
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	issuerBaseURL := fmt.Sprintf("http://host.docker.internal:%d", port)

	runIssuanceFlow(t, ln, nodeInternalURL, "wallet", walletDID, issuerBaseURL, "issuer")
}

// startNode boots the Nuts node container (acting as issuer signer + wallet),
// publishing its public (8080) and internal (8081) APIs on the same host ports.
func startNode(t *testing.T, ctx context.Context) {
	t.Helper()

	// Node config with the public url on localhost:8080 so did:web resolves from
	// the host-side issuer over the published port.
	cfgSrc, err := os.ReadFile(filepath.Join("..", "..", "deploy", "nuts", "nuts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.ReplaceAll(string(cfgSrc), "http://nutsnode:8080", nodeURL)
	cfgPath := filepath.Join(t.TempDir(), "nuts.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	contextPath, err := filepath.Abs(filepath.Join("..", "..", "deploy", "nuts", "contexts", "gis.jsonld"))
	if err != nil {
		t.Fatal(err)
	}

	req := testcontainers.ContainerRequest{
		Image: "nutsfoundation/nuts-node:project-gf-pilot",
		Env: map[string]string{
			"NUTS_CONFIGFILE": "/nuts/nuts.yaml",
			"NUTS_VERBOSITY":  "debug",
		},
		ExposedPorts: []string{nodePublicPort + "/tcp", nodeInternalPort + "/tcp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfgPath, ContainerFilePath: "/nuts/nuts.yaml", FileMode: 0o644},
			{HostFilePath: contextPath, ContainerFilePath: "/nuts/contexts/gis.jsonld", FileMode: 0o644},
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			anyIP := netip.MustParseAddr("0.0.0.0")
			hc.PortBindings = network.PortMap{
				network.MustParsePort(nodePublicPort + "/tcp"):   {{HostIP: anyIP, HostPort: nodePublicPort}},
				network.MustParsePort(nodeInternalPort + "/tcp"): {{HostIP: anyIP, HostPort: nodeInternalPort}},
			}
			// Lets the node reach the host-side issuer at host.docker.internal (Linux).
			hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
		},
		WaitingFor: wait.ForHTTP("/status").WithPort(nodeInternalPort + "/tcp").WithStartupTimeout(90 * time.Second),
	}
	node, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start nuts node: %v", err)
	}
	t.Cleanup(func() { _ = node.Terminate(context.Background()) })
}

func createSubject(t *testing.T, subject string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"subject": subject})
	resp, err := http.Post(nodeInternalURL+"/internal/vdr/v2/subject", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create subject %q: %v", subject, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("create subject %q: HTTP %d: %s", subject, resp.StatusCode, raw)
	}
}

func resolveDID(t *testing.T, subject string) string {
	t.Helper()
	resp, err := http.Get(nodeInternalURL + "/internal/vdr/v2/subject/" + subject)
	if err != nil {
		t.Fatalf("resolve subject %q: %v", subject, err)
	}
	defer resp.Body.Close()
	var dids []string
	if err := json.NewDecoder(resp.Body).Decode(&dids); err != nil || len(dids) == 0 {
		t.Fatalf("resolve subject %q: %v (%v)", subject, err, dids)
	}
	return dids[0]
}

// runIssuanceFlow stands up the in-process issuer on ln and drives the full
// OpenID4VCI flow against the running Nuts node, then asserts the credential
// lands in the wallet. issuerBaseURL is how the node reaches the in-process
// issuer; walletSubject is the holder subject on the node.
func runIssuanceFlow(t *testing.T, ln net.Listener, nodeInternal, walletSubject, walletDID, issuerBaseURL, issuerSubject string) {
	t.Helper()
	renderer, err := web.New("Nuts Credential Issuer")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimRight(issuerBaseURL, "/")
	nuts := nutsclient.New(strings.TrimRight(nodeInternal, "/"), nil)
	verifier := proof.NewVerifier(didweb.New(true, nil), base, time.Now)
	svc := issuer.NewService(nuts, nuts, time.Now, issuer.Config{
		IssuerSubject: issuerSubject,
	})
	adapter, err := openid4vci.New(openid4vci.Options{
		BaseURL:    base,
		Service:    svc,
		Renderer:   renderer,
		Proofs:     verifier,
		LoginPath:  eherkenning.LoginPath,
		SessionTTL: 10 * time.Minute,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := eherkenning.New("Voorbeeld Dienstverlener B.V.", "90000001", "Nuts Credential Issuer", adapter.OnAuthenticated)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	adapter.RegisterRoutes(mux)
	authenticator.RegisterRoutes(mux)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// 1. Ask the node (wallet) to start the OpenID4VCI flow against our issuer.
	reqBody, _ := json.Marshal(map[string]any{
		"wallet_did": walletDID,
		"issuer":     base,
		"authorization_details": []map[string]any{
			{"type": "openid_credential", "credential_configuration_id": "ServiceProviderCredential"},
		},
		"redirect_uri": "http://localhost/done",
	})
	startResp := postJSON(t, nodeInternal+"/internal/auth/v2/"+walletSubject+"/request-credential", reqBody)
	var start struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(startResp, &start); err != nil {
		t.Fatalf("parse request-credential response: %v (%s)", err, startResp)
	}
	if start.RedirectURI == "" {
		t.Fatalf("node did not return a redirect_uri: %s", startResp)
	}

	// 2. Act as the browser. /authorize redirects to the login page and sets a
	// session cookie, so this client follows redirects and keeps cookies.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Timeout: 30 * time.Second, Jar: jar}
	// For the final node callback we must NOT follow the redirect into the node's
	// own redirect_uri; we just want the node to complete the exchange.
	noFollow := &http.Client{
		Timeout:       30 * time.Second,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The issuer is advertised at issuerBaseURL (how the node reaches it). The test
	// process reaches the same listener via localhost, so rewrite the host for the
	// browser-side requests.
	localBase := strings.ReplaceAll(base, "host.docker.internal", "localhost")
	loginURL := strings.ReplaceAll(start.RedirectURI, "host.docker.internal", "localhost")

	httpGet(t, browser, loginURL) // follows the 302 to /login, setting the session cookie
	httpPostForm(t, browser, localBase+eherkenning.LoginPath, url.Values{})
	redirectHTML := httpPostForm(t, browser, localBase+"/consent", url.Values{})

	action := firstSubmatch(t, `action="([^"]+)"`, redirectHTML, "redirect action")
	code := firstSubmatch(t, `name="code"\s+value="([^"]+)"`, redirectHTML, "code")
	state := firstSubmatch(t, `name="state"\s+value="([^"]+)"`, redirectHTML, "state")

	callbackURL := action + "?" + url.Values{"code": {code}, "state": {state}}.Encode()
	resp, err := noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("node callback: %v", err)
	}
	resp.Body.Close()

	// 3. The node should now hold a ServiceProviderCredential for the wallet DID.
	if !walletHoldsCredential(t, nodeInternal, walletSubject, walletDID) {
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
			// The wallet returns its credentials as JWTs; the type and subject are
			// inside the base64 payload, so decode each before matching.
			var jwts []string
			if json.Unmarshal(body, &jwts) == nil {
				for _, j := range jwts {
					if vc := decodeVC(j); vc != nil &&
						typeContains(vc, "ServiceProviderCredential") &&
						subjectID(vc) == walletDID {
						return true
					}
				}
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	return false
}

// decodeVC extracts the "vc" claim from a jwt_vc credential's base64 payload.
func decodeVC(jwtVC string) map[string]any {
	parts := strings.Split(jwtVC, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		VC map[string]any `json:"vc"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims.VC
}

func typeContains(vc map[string]any, want string) bool {
	types, _ := vc["type"].([]any)
	for _, ty := range types {
		if ty == want {
			return true
		}
	}
	return false
}

func subjectID(vc map[string]any) string {
	subj, ok := vc["credentialSubject"].(map[string]any)
	if !ok {
		if list, ok := vc["credentialSubject"].([]any); ok && len(list) > 0 {
			subj, _ = list[0].(map[string]any)
		}
	}
	id, _ := subj["id"].(string)
	return id
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
