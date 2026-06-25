// Package didweb resolves did:web DID documents over HTTP. It implements the
// DID-resolution port used by proof verification.
package didweb

import (
	"context"
	"encoding/json"
	"errors"
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

// New returns a did:web resolver. When insecure is true, resolution also tries
// plain HTTP in addition to HTTPS (demo only).
func New(insecure bool, httpClient *http.Client) *Resolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Resolver{insecure: insecure, http: httpClient}
}

// Resolve fetches and parses the DID document for a did:web DID. It tries HTTPS,
// and additionally plain HTTP when the resolver is insecure.
func (r *Resolver) Resolve(ctx context.Context, didStr string) (*did.Document, error) {
	d, err := did.ParseDID(didStr)
	if err != nil {
		return nil, fmt.Errorf("parse DID %q: %w", didStr, err)
	}
	if d.Method != "web" {
		return nil, fmt.Errorf("unsupported DID method %q, only did:web is supported", d.Method)
	}
	path, err := documentPath(*d)
	if err != nil {
		return nil, err
	}

	schemes := []string{"https"}
	if r.insecure {
		schemes = append(schemes, "http")
	}
	var errs []error
	for _, scheme := range schemes {
		doc, err := r.fetch(ctx, scheme+"://"+path)
		if err == nil {
			return doc, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("resolve %s: %w", didStr, errors.Join(errs...))
}

func (r *Resolver) fetch(ctx context.Context, docURL string) (*did.Document, error) {
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
		return nil, fmt.Errorf("%s returned HTTP %d", docURL, resp.StatusCode)
	}
	var doc did.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document from %s: %w", docURL, err)
	}
	return &doc, nil
}

// documentPath returns the host+path of a did:web DID document URL (without
// scheme), per the did:web method spec.
func documentPath(d did.DID) (string, error) {
	parts := strings.Split(d.ID, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid did:web host: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("did:web has empty host")
	}
	if len(parts) == 1 {
		return host + "/.well-known/did.json", nil
	}
	segments := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		seg, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("invalid did:web path segment: %w", err)
		}
		segments = append(segments, seg)
	}
	return host + "/" + strings.Join(segments, "/") + "/did.json", nil
}
