// Package didweb resolves did:web DID documents over HTTP. It implements the
// DID-resolution port used by proof verification.
package didweb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/did"
)

// Resolver resolves did:web documents over HTTP.
type Resolver struct {
	insecure bool
	http     *http.Client
}

// New returns a did:web resolver. When insecure is true, resolution uses plain
// HTTP instead of HTTPS (demo only).
func New(insecure bool, httpClient *http.Client) *Resolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Resolver{insecure: insecure, http: httpClient}
}

// Resolve fetches and parses the DID document for a did:web DID.
func (r *Resolver) Resolve(ctx context.Context, didStr string) (*did.Document, error) {
	d, err := did.ParseDID(didStr)
	if err != nil {
		return nil, fmt.Errorf("parse DID %q: %w", didStr, err)
	}
	docURL, err := documentURL(*d, r.insecure)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", docURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web resolution of %s returned HTTP %d", docURL, resp.StatusCode)
	}
	var doc did.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}
	return &doc, nil
}

// documentURL converts a did:web DID to its DID document URL, per the did:web spec.
func documentURL(d did.DID, insecure bool) (string, error) {
	if d.Method != "web" {
		return "", fmt.Errorf("unsupported DID method %q, only did:web is supported", d.Method)
	}
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	parts := strings.Split(d.ID, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid did:web host: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("did:web has empty host")
	}
	if len(parts) == 1 {
		return scheme + "://" + host + "/.well-known/did.json", nil
	}
	segments := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		seg, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("invalid did:web path segment: %w", err)
		}
		segments = append(segments, seg)
	}
	return scheme + "://" + host + "/" + strings.Join(segments, "/") + "/did.json", nil
}
