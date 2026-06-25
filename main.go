// Command nuts-credential-issuer is an OpenID4VCI issuer for the
// ServiceProviderCredential. It authenticates a vendor, validates the wallet's
// credential-request proof, mints the credential via a Nuts node, and returns it
// over the OpenID4VCI credential endpoint.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/auth/eherkenning"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/config"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/didweb"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuer"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/nutsclient"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/openid4vci"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/proof"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/web"
)

// sessionTTL bounds how long an in-flight issuance and its c_nonces live, and is
// reported as the access-token expires_in.
const sessionTTL = 10 * time.Minute

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

	if !cfg.Demo {
		slog.Error("no authentication method configured: set CIS_DEMO=true to use the fake eHerkenning authenticator")
		os.Exit(1)
	}

	renderer, err := web.New(cfg.Title)
	if err != nil {
		slog.Error("failed to load templates", "err", err)
		os.Exit(1)
	}

	// Outbound adapters.
	nuts := nutsclient.New(cfg.NutsNodeURL, &http.Client{Timeout: 30 * time.Second})
	verifier := proof.NewVerifier(didweb.New(cfg.Demo, &http.Client{Timeout: 10 * time.Second}), cfg.BaseURL, time.Now)

	// Application service (protocol-agnostic).
	service := issuer.NewService(nuts, nuts, time.Now, issuer.Config{
		IssuerSubject: cfg.IssuerSubject,
		ConfigID:      credentials.ServiceProviderCredentialType,
	})

	// Inbound HTTP adapter (owns the OAuth/OpenID4VCI protocol and session state).
	adapter, err := openid4vci.New(openid4vci.Options{
		BaseURL:             cfg.BaseURL,
		Service:             service,
		Renderer:            renderer,
		Proofs:              verifier,
		LoginPath:           eherkenning.LoginPath,
		CallbackRewriteFrom: cfg.CallbackRewriteFrom,
		CallbackRewriteTo:   cfg.CallbackRewriteTo,
		SessionTTL:          sessionTTL,
		Now:                 time.Now,
	})
	if err != nil {
		slog.Error("failed to start issuer", "err", err)
		os.Exit(1)
	}
	defer adapter.Close()

	// Demo authenticator, wired to call back into the adapter on success.
	slog.Warn("DEMO mode enabled — using the FAKE eHerkenning authenticator; it performs NO identity verification and must never be used in a hosted deployment")
	authenticator, err := eherkenning.New(cfg.DemoOrgName, cfg.DemoOrgIdentifier, cfg.Title, adapter.OnAuthenticated)
	if err != nil {
		slog.Error("failed to build authenticator", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           adapter.Handler(authenticator),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	slog.Info("nuts-credential-issuer listening",
		"addr", cfg.ListenAddr, "base_url", cfg.BaseURL, "issuer_subject", cfg.IssuerSubject, "nuts_node", cfg.NutsNodeURL)
	if err := serve(srv); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// serve runs the HTTP server until SIGINT/SIGTERM, then shuts it down gracefully.
func serve(srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
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
