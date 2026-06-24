package issuer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// Config holds the issuer's non-port settings.
type Config struct {
	// IssuerSubject is the Nuts subject whose did:web the credential is issued from.
	IssuerSubject string
	// ConfigID is the single credential_configuration_id this issuer offers.
	ConfigID string
	// CredentialValidity is how long an issued credential is valid for.
	CredentialValidity time.Duration
	// AccessTokenTTL is reported as expires_in on the token response.
	AccessTokenTTL time.Duration
}

// Service orchestrates the issuance use-cases over the domain and the ports.
type Service struct {
	store    Store
	minter   Minter
	subjects SubjectResolver
	proofs   ProofVerifier
	now      func() time.Time
	cfg      Config

	didMu     sync.Mutex
	issuerDID string // cached resolution of cfg.IssuerSubject
}

// NewService constructs the application service.
func NewService(store Store, minter Minter, subjects SubjectResolver, proofs ProofVerifier, now func() time.Time, cfg Config) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, minter: minter, subjects: subjects, proofs: proofs, now: now, cfg: cfg}
}

// CredentialType returns the credential configuration id this issuer offers.
func (s *Service) CredentialType() string { return s.cfg.ConfigID }

// StartAuthorization validates the request, creates an issuance and returns its
// id (used to tie authentication back to the flow).
func (s *Service) StartAuthorization(p AuthorizeParams) (string, error) {
	configID, err := s.resolveConfigID(p.RequestedConfigID)
	if err != nil {
		return "", err
	}
	id := randID()
	s.store.Create(issuance.New(issuance.Params{
		ID:            id,
		RedirectURI:   p.RedirectURI,
		OAuthState:    p.OAuthState,
		CodeChallenge: p.CodeChallenge,
		ConfigID:      configID,
		Recipient:     p.Recipient,
	}, s.now()))
	return id, nil
}

func (s *Service) resolveConfigID(requested string) (string, error) {
	if requested == "" || requested == s.cfg.ConfigID {
		return s.cfg.ConfigID, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedCredential, requested)
}

// Authenticate records the authenticated organisation and returns the consent view.
func (s *Service) Authenticate(sessionID string, org issuance.Organization) (ConsentView, error) {
	iss, ok := s.store.Get(sessionID)
	if !ok {
		return ConsentView{}, ErrSessionNotFound
	}
	if err := iss.Authenticate(org); err != nil {
		return ConsentView{}, err
	}
	return ConsentView{
		SessionID:      iss.ID(),
		CredentialType: iss.ConfigID(),
		Organization:   org,
		Recipient:      iss.Recipient(),
		Services:       credentials.DefaultServiceProviderServices,
	}, nil
}

// Consent records the chosen services, mints an authorization code and returns
// the redirect view.
func (s *Service) Consent(sessionID string, services []string) (RedirectView, error) {
	iss, ok := s.store.Get(sessionID)
	if !ok {
		return RedirectView{}, ErrSessionNotFound
	}
	code := randID()
	if err := iss.GrantConsent(services, code); err != nil {
		return RedirectView{}, err
	}
	s.store.BindCode(code, iss.ID())
	return RedirectView{Action: iss.RedirectURI(), Code: code, State: iss.OAuthState()}, nil
}

// ExchangeToken redeems an authorization code for an access token + c_nonce.
func (s *Service) ExchangeToken(code, verifier, redirectURI string) (TokenResult, error) {
	iss, ok := s.store.TakeByCode(code)
	if !ok {
		return TokenResult{}, fmt.Errorf("%w: unknown or expired code", ErrInvalidGrant)
	}
	token := randID()
	if err := iss.ExchangeCode(verifier, redirectURI, token); err != nil {
		return TokenResult{}, fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	s.store.BindToken(token, iss.ID())
	nonce := randID()
	s.store.PutNonce(nonce)
	return TokenResult{AccessToken: token, CNonce: nonce, ExpiresIn: int(s.cfg.AccessTokenTTL.Seconds())}, nil
}

// IssueNonce hands out a fresh c_nonce (the OpenID4VCI nonce endpoint).
func (s *Service) IssueNonce() string {
	nonce := randID()
	s.store.PutNonce(nonce)
	return nonce
}

// IssueCredential validates the request proof, mints the credential and returns
// it verbatim.
func (s *Service) IssueCredential(ctx context.Context, token, proofJWT string) (json.RawMessage, error) {
	iss, ok := s.store.ByToken(token)
	if !ok {
		return nil, ErrInvalidToken
	}
	res, err := s.proofs.Verify(ctx, proofJWT)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if !s.store.ConsumeNonce(res.Nonce) {
		return nil, fmt.Errorf("%w: nonce is missing, unknown or expired", ErrInvalidProof)
	}

	issuerDID, err := s.resolveIssuerDID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer DID: %w", err)
	}
	org := iss.Organization()
	cred := credentials.BuildServiceProviderCredential(issuerDID, credentials.ServiceProvider{
		DID:       res.HolderDID,
		LegalName: org.LegalName,
		Services:  iss.Services(),
	}, s.cfg.CredentialValidity, s.now())

	vc, err := s.minter.IssueVC(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("mint credential: %w", err)
	}
	if err := iss.MarkIssued(); err != nil {
		return nil, err
	}
	return vc, nil
}

// resolveIssuerDID resolves and caches the issuer DID from its Nuts subject. It
// is resolved lazily so the subject may be created (via Nuts Admin) after start.
func (s *Service) resolveIssuerDID(ctx context.Context) (string, error) {
	s.didMu.Lock()
	defer s.didMu.Unlock()
	if s.issuerDID != "" {
		return s.issuerDID, nil
	}
	did, err := s.subjects.SubjectDID(ctx, s.cfg.IssuerSubject)
	if err != nil {
		return "", err
	}
	s.issuerDID = did
	return did, nil
}

func randID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
