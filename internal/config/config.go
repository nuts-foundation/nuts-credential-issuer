// Package config loads the issuer configuration from CIS_* environment variables
// using koanf, unmarshalled over struct-initialised defaults.
package config

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// Config holds the runtime configuration of the credential issuer. Field defaults
// are set in Load; environment variables (CIS_<UPPER_FIELD>) override them.
type Config struct {
	// ListenAddr is the address the HTTP server binds to (e.g. ":8080").
	ListenAddr string `koanf:"listen_addr"`
	// Title is the issuer's display name, shown in the UI.
	Title string `koanf:"title"`
	// BaseURL is the public base URL of the issuer. It doubles as the OpenID4VCI
	// Credential Issuer Identifier and the OAuth issuer, and is the base for the
	// authorize, token, credential and nonce endpoints.
	BaseURL string `koanf:"base_url"`

	// IssuerSubject is the Nuts subject whose did:web the issuer issues from. The
	// issuer resolves the DID from the node at runtime, so no DID is hardcoded;
	// the subject is created via Nuts Admin. The signing key lives in the node.
	IssuerSubject string `koanf:"issuer_subject"`
	// NutsNodeURL is the base URL of the Nuts node's internal API.
	NutsNodeURL string `koanf:"nuts_node_url"`

	// Demo enables the fake eHerkenning authenticator. It also allows resolving
	// holder did:web over plain HTTP, for local non-TLS Nuts nodes.
	Demo bool `koanf:"demo"`
	// DemoOrgName / DemoOrgIdentifier are the identity the fake login asserts.
	DemoOrgName       string `koanf:"demo_org_name"`
	DemoOrgIdentifier string `koanf:"demo_org_identifier"`
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

	// CIS_NUTS_NODE_URL -> nuts_node_url, matching the koanf field tags.
	k := koanf.New(".")
	if err := k.Load(env.Provider("CIS_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "CIS_"))
	}), nil); err != nil {
		return Config{}, fmt.Errorf("load environment: %w", err)
	}
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			WeaklyTypedInput: true, // env values are strings; coerce to bool etc.
			Result:           &cfg,
		},
	}); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}

	if cfg.IssuerSubject == "" {
		return Config{}, fmt.Errorf("CIS_ISSUER_SUBJECT is required")
	}
	return cfg, nil
}
