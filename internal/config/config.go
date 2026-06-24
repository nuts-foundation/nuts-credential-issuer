// Package config loads the issuer configuration from environment variables
// using koanf.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// Config holds the runtime configuration of the credential issuer.
type Config struct {
	// ListenAddr is the address the HTTP server binds to (e.g. ":8080").
	ListenAddr string
	// Title is the issuer's display name, shown in the UI.
	Title string
	// BaseURL is the public base URL of the issuer. It doubles as the
	// OpenID4VCI Credential Issuer Identifier and the OAuth issuer, and is used
	// for the token, credential and nonce endpoints — the URLs a wallet (Nuts
	// node) calls server-to-server. No trailing slash.
	BaseURL string
	// AuthorizationEndpoint is the URL advertised as the OAuth
	// authorization_endpoint. This is the one URL a browser is redirected to, so
	// in a containerised setup it can differ from BaseURL (e.g. a localhost URL
	// while BaseURL is a Docker service name). Defaults to BaseURL + "/authorize".
	AuthorizationEndpoint string

	// IssuerSubject is the Nuts subject whose did:web the issuer issues from. The
	// issuer resolves the DID from the node at runtime, so no DID is hardcoded;
	// the subject is created via Nuts Admin. The signing key lives in the node.
	IssuerSubject string
	// NutsNodeURL is the base URL of the Nuts node's internal API.
	NutsNodeURL string

	// CredentialValidity is how long an issued credential is valid for.
	CredentialValidity time.Duration

	// Demo enables the fake eHerkenning authenticator. Without it the issuer has
	// no authenticator and refuses to start, so the fake login can never be the
	// default in a hosted deployment.
	Demo bool
	// DemoOrgName / DemoOrgIdentifier are the identity the fake login asserts.
	DemoOrgName       string
	DemoOrgIdentifier string

	// InsecureDIDWeb allows resolving did:web holder DIDs over plain HTTP. Only
	// honoured together with Demo; required to validate proofs against a non-TLS
	// Nuts node in local runs.
	InsecureDIDWeb bool

	// CallbackRewriteFrom/To rewrite the host of the wallet's callback URL when
	// the issuer renders the browser redirect. For demos where NUTS_URL is an
	// internal hostname the browser cannot resolve (e.g. a Docker service name),
	// set "internal-host:port=browser-host:port". The original URL is still used
	// for the /token redirect_uri check.
	CallbackRewriteFrom string
	CallbackRewriteTo   string
}

// envPrefix namespaces all environment variables of the Credential ISsuer.
const envPrefix = "CIS_"

var defaults = map[string]any{
	"CIS_LISTEN_ADDR":         ":8080",
	"CIS_TITLE":               "Nuts Credential Issuer",
	"CIS_BASE_URL":            "http://localhost:8080",
	"CIS_ISSUER_SUBJECT":      "issuer",
	"CIS_NUTS_NODE_URL":       "http://localhost:8081",
	"CIS_CREDENTIAL_VALIDITY": "8760h", // one year
	"CIS_DEMO_ORG_NAME":       "Voorbeeld Dienstverlener B.V.",
	"CIS_DEMO_ORG_IDENTIFIER": "90000001",
}

// Load reads the configuration from CIS_* environment variables and validates it.
func Load() (Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return Config{}, fmt.Errorf("load defaults: %w", err)
	}
	if err := k.Load(env.Provider(envPrefix, ".", func(s string) string { return s }), nil); err != nil {
		return Config{}, fmt.Errorf("load environment: %w", err)
	}

	c := Config{
		ListenAddr:            k.String("CIS_LISTEN_ADDR"),
		Title:                 k.String("CIS_TITLE"),
		BaseURL:               strings.TrimRight(k.String("CIS_BASE_URL"), "/"),
		AuthorizationEndpoint: k.String("CIS_AUTHORIZATION_ENDPOINT"),
		IssuerSubject:         k.String("CIS_ISSUER_SUBJECT"),
		NutsNodeURL:           strings.TrimRight(k.String("CIS_NUTS_NODE_URL"), "/"),
		Demo:                  k.Bool("CIS_DEMO"),
		DemoOrgName:           k.String("CIS_DEMO_ORG_NAME"),
		DemoOrgIdentifier:     k.String("CIS_DEMO_ORG_IDENTIFIER"),
		InsecureDIDWeb:        k.Bool("CIS_DID_WEB_INSECURE"),
	}

	d, err := time.ParseDuration(k.String("CIS_CREDENTIAL_VALIDITY"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid CIS_CREDENTIAL_VALIDITY %q: %w", k.String("CIS_CREDENTIAL_VALIDITY"), err)
	}
	c.CredentialValidity = d

	if c.AuthorizationEndpoint == "" {
		c.AuthorizationEndpoint = c.BaseURL + "/authorize"
	}

	if rewrite := k.String("CIS_BROWSER_CALLBACK_REWRITE"); rewrite != "" {
		from, to, ok := strings.Cut(rewrite, "=")
		if !ok || from == "" || to == "" {
			return Config{}, fmt.Errorf("CIS_BROWSER_CALLBACK_REWRITE must be \"from=to\"")
		}
		c.CallbackRewriteFrom, c.CallbackRewriteTo = from, to
	}

	if c.IssuerSubject == "" {
		return Config{}, fmt.Errorf("CIS_ISSUER_SUBJECT is required")
	}
	if c.InsecureDIDWeb && !c.Demo {
		return Config{}, fmt.Errorf("CIS_DID_WEB_INSECURE may only be used with CIS_DEMO=true")
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
