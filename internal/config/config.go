// Package config loads the issuer configuration from CIS_* environment variables
// using koanf, over struct-initialised defaults.
package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// Config holds the runtime configuration of the credential issuer.
type Config struct {
	// ListenAddr is the address the HTTP server binds to (e.g. ":8080").
	ListenAddr string
	// Title is the issuer's display name, shown in the UI.
	Title string
	// BaseURL is the public base URL of the issuer. It doubles as the OpenID4VCI
	// Credential Issuer Identifier and the OAuth issuer, and is the base for the
	// authorize, token, credential and nonce endpoints.
	BaseURL string

	// IssuerSubject is the Nuts subject whose did:web the issuer issues from. The
	// issuer resolves the DID from the node at runtime, so no DID is hardcoded;
	// the subject is created via Nuts Admin. The signing key lives in the node.
	IssuerSubject string
	// NutsNodeURL is the base URL of the Nuts node's internal API.
	NutsNodeURL string

	// Demo enables the fake eHerkenning authenticator. It also allows resolving
	// holder did:web over plain HTTP, for local non-TLS Nuts nodes.
	Demo bool
	// DemoOrgName / DemoOrgIdentifier are the identity the fake login asserts.
	DemoOrgName       string
	DemoOrgIdentifier string

	// CallbackRewriteFrom/To rewrite the host of the wallet's callback URL when
	// the issuer renders the browser redirect. For demos where NUTS_URL is an
	// internal hostname the browser cannot resolve (e.g. a Docker service name),
	// set "internal-host:port=browser-host:port". The original URL is still used
	// for the /token redirect_uri check.
	CallbackRewriteFrom string
	CallbackRewriteTo   string
}

// Load reads the configuration from CIS_* environment variables and validates it.
func Load() (Config, error) {
	// Defaults live in the struct; environment values override them.
	cfg := Config{
		ListenAddr:        ":8080",
		Title:             "Nuts Credential Issuer",
		BaseURL:           "http://localhost:8080",
		IssuerSubject:     "issuer",
		NutsNodeURL:       "http://localhost:8081",
		DemoOrgName:       "Voorbeeld Dienstverlener B.V.",
		DemoOrgIdentifier: "90000001",
	}

	k := koanf.New(".")
	if err := k.Load(env.Provider("CIS_", ".", func(s string) string { return s }), nil); err != nil {
		return Config{}, fmt.Errorf("load environment: %w", err)
	}

	str := func(key string, dst *string) {
		if k.Exists(key) {
			*dst = k.String(key)
		}
	}
	boolean := func(key string, dst *bool) {
		if k.Exists(key) {
			*dst = k.Bool(key)
		}
	}
	str("CIS_LISTEN_ADDR", &cfg.ListenAddr)
	str("CIS_TITLE", &cfg.Title)
	str("CIS_BASE_URL", &cfg.BaseURL)
	str("CIS_ISSUER_SUBJECT", &cfg.IssuerSubject)
	str("CIS_NUTS_NODE_URL", &cfg.NutsNodeURL)
	boolean("CIS_DEMO", &cfg.Demo)
	str("CIS_DEMO_ORG_NAME", &cfg.DemoOrgName)
	str("CIS_DEMO_ORG_IDENTIFIER", &cfg.DemoOrgIdentifier)

	if rewrite := k.String("CIS_BROWSER_CALLBACK_REWRITE"); rewrite != "" {
		from, to, ok := strings.Cut(rewrite, "=")
		if !ok || from == "" || to == "" {
			return Config{}, fmt.Errorf("CIS_BROWSER_CALLBACK_REWRITE must be \"from=to\"")
		}
		cfg.CallbackRewriteFrom, cfg.CallbackRewriteTo = from, to
	}

	if cfg.IssuerSubject == "" {
		return Config{}, fmt.Errorf("CIS_ISSUER_SUBJECT is required")
	}
	return cfg, nil
}
