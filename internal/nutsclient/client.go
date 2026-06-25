// Package nutsclient is a thin client for the Nuts node internal issuer API.
package nutsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/urls"
)

// Client talks to a Nuts node's internal API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client for the Nuts node reachable at baseURL (its internal API
// base, e.g. "http://localhost:8081").
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: baseURL, http: httpClient}
}

// ResolveDID returns the did:web of a Nuts subject, looked up via
// GET /internal/vdr/v2/subject/{subject}. The issuer uses this to resolve its own
// issuer DID from a configured subject name, so no DID is hardcoded. It errors if
// the subject has no did:web, or more than one (ambiguous).
func (c *Client) ResolveDID(ctx context.Context, subject string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urls.Join(c.baseURL, "internal/vdr/v2/subject", subject), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve subject %q: %w", subject, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read subject %q response: %w", subject, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve subject %q: Nuts node returned HTTP %d: %s", subject, resp.StatusCode, string(raw))
	}
	var dids []string
	if err := json.Unmarshal(raw, &dids); err != nil {
		return "", fmt.Errorf("parse subject %q DIDs: %w", subject, err)
	}
	var webDIDs []string
	for _, d := range dids {
		if strings.HasPrefix(d, "did:web:") {
			webDIDs = append(webDIDs, d)
		}
	}
	switch len(webDIDs) {
	case 1:
		return webDIDs[0], nil
	case 0:
		return "", fmt.Errorf("subject %q has no did:web", subject)
	default:
		return "", fmt.Errorf("subject %q has multiple did:web DIDs: %v", subject, webDIDs)
	}
}

// issueVCRequest is the body of POST /internal/vcr/v2/issuer/vc.
type issueVCRequest struct {
	Context           []string `json:"@context,omitempty"`
	Type              []string `json:"type"`
	Issuer            string   `json:"issuer"`
	CredentialSubject any      `json:"credentialSubject"`
	ExpirationDate    string   `json:"expirationDate,omitempty"`
	// Format selects the proof format. We use "jwt_vc"; the node then returns
	// the credential as a JSON-encoded JWT string.
	Format string `json:"format,omitempty"`
	// WithStatusList2021Revocation adds a StatusList2021 credentialStatus so the
	// credential can be revoked (only valid for did:web issuers).
	WithStatusList2021Revocation bool `json:"withStatusList2021Revocation,omitempty"`
}

// Mint mints a verifiable credential via the Nuts node, mapping the neutral
// domain credential to the node's API. The returned json.RawMessage is the
// credential exactly as the node produced it (a JSON string holding a JWT for
// format "jwt_vc"), ready to embed in an OpenID4VCI credential response.
func (c *Client) Mint(ctx context.Context, cred credentials.Credential) (json.RawMessage, error) {
	body := issueVCRequest{
		Context:                      cred.Context,
		Type:                         cred.Type,
		Issuer:                       cred.IssuerDID,
		CredentialSubject:            cred.Subject,
		ExpirationDate:               cred.ExpirationDate,
		Format:                       cred.Format,
		WithStatusList2021Revocation: cred.Revocable,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal issue request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urls.Join(c.baseURL, "internal/vcr/v2/issuer/vc"), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call Nuts node: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read Nuts node response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Nuts node issuer returned HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return json.RawMessage(bytes.TrimSpace(raw)), nil
}
