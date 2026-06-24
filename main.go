// Command nuts-credential-issuer is an OpenID4VCI issuer for the
// ServiceProviderCredential. It authenticates a vendor, validates the wallet's
// credential-request proof, mints the credential via a Nuts node, and returns it
// over the OpenID4VCI credential endpoint.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth/eherkenning"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/config"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

func main() {
	// "healthcheck" mode is used by the container HEALTHCHECK; the distroless
	// image has no shell or curl, so the binary checks its own /health endpoint.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "err", err)
		os.Exit(1)
	}

	renderer, err := web.New(cfg.Title)
	if err != nil {
		slog.Error("failed to load templates", "err", err)
		os.Exit(1)
	}

	authenticator, err := buildAuthenticator(cfg)
	if err != nil {
		slog.Error("failed to build authenticator", "err", err)
		os.Exit(1)
	}

	issuer, err := openid4vci.New(openid4vci.Options{
		BaseURL:               cfg.BaseURL,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint,
		IssuerSubject:         cfg.IssuerSubject,
		CredentialValidity:    cfg.CredentialValidity,
		Authenticator:         authenticator,
		Nuts:                  nutsclient.New(cfg.NutsNodeURL, &http.Client{Timeout: 30 * time.Second}),
		Renderer:              renderer,
		InsecureDIDWeb:        cfg.InsecureDIDWeb,
		CallbackRewriteFrom:   cfg.CallbackRewriteFrom,
		CallbackRewriteTo:     cfg.CallbackRewriteTo,
		HTTPClient:            &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		slog.Error("failed to start issuer", "err", err)
		os.Exit(1)
	}
	defer issuer.Close()

	slog.Info("nuts-credential-issuer listening",
		"addr", cfg.ListenAddr, "base_url", cfg.BaseURL, "issuer_subject", cfg.IssuerSubject, "nuts_node", cfg.NutsNodeURL)
	if err := http.ListenAndServe(cfg.ListenAddr, issuer.Handler()); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// buildAuthenticator wires the configured authentication method. Only the demo
// fake eHerkenning exists today, so the issuer refuses to start unless DEMO is
// set — the fake login can never be the default in a hosted deployment.
func buildAuthenticator(cfg config.Config) (auth.Authenticator, error) {
	if !cfg.Demo {
		return nil, fmt.Errorf("no authentication method configured: set DEMO=true to use the fake eHerkenning authenticator")
	}
	slog.Warn("DEMO mode enabled — using the FAKE eHerkenning authenticator; it performs NO identity verification and must never be used in a hosted deployment")
	return eherkenning.New(cfg.DemoOrgName, cfg.DemoOrgIdentifier, cfg.Title)
}

// healthcheck probes the local /health endpoint and returns a process exit code.
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		return 1
	}
	addr := cfg.ListenAddr
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
