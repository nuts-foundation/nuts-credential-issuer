package openid4vci

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// verifyPKCE reports whether the code_verifier matches the S256 code_challenge.
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

// credentialRequest models the OpenID4VCI credential request. It accepts both
// the OpenID4VCI 1.0 plural "proofs" shape and the older singular "proof" shape,
// since which one the wallet sends is Nuts-node-version dependent.
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

// requestedConfigID extracts the requested credential_configuration_id from the
// authorization_details parameter ("" when none is given).
func requestedConfigID(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	var entries []struct {
		Type                      string `json:"type"`
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("invalid authorization_details: %w", err)
	}
	for _, e := range entries {
		if e.Type == "openid_credential" {
			return e.CredentialConfigurationID, nil
		}
	}
	return "", nil
}

// parseRecipient derives a human-readable label for the recipient wallet from
// its OAuth client_id, split into a prominent host and a muted detail (path or
// DID identifier, often a GUID).
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
