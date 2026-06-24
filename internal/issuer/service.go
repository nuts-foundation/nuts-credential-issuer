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
}

// Service orchestrates the issuance use-cases over the domain and the ports. It
// is stateless: the inbound adapter owns the in-flight sessions and passes the
// issuance aggregate into each step.
type Service struct {
	minter   Minter
	subjects SubjectResolver
	now      func() time.Time
	cfg      Config

	didMu     sync.Mutex
	issuerDID string // cached resolution of cfg.IssuerSubject
}

// NewService constructs the application service.
func NewService(minter Minter, subjects SubjectResolver, now func() time.Time, cfg Config) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{minter: minter, subjects: subjects, now: now, cfg: cfg}
}

// CredentialType returns the credential configuration id this issuer offers.
func (s *Service) CredentialType() string { return s.cfg.ConfigID }

// Start validates the request and creates a new issuance aggregate.
func (s *Service) Start(p StartParams) (*issuance.Issuance, error) {
	configID, err := s.resolveConfigID(p.RequestedConfigID)
	if err != nil {
		return nil, err
	}
	return issuance.New(issuance.Params{
		ID:        randID(),
		ConfigID:  configID,
		Recipient: p.Recipient,
	}, s.now()), nil
}

func (s *Service) resolveConfigID(requested string) (string, error) {
	if requested == "" || requested == s.cfg.ConfigID {
		return s.cfg.ConfigID, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedCredential, requested)
}

// Authenticate records the authenticated organisation and returns the consent
// details to present.
func (s *Service) Authenticate(iss *issuance.Issuance, org issuance.Organization) (ConsentDetails, error) {
	if err := iss.Authenticate(org); err != nil {
		return ConsentDetails{}, err
	}
	return ConsentDetails{
		Organization:   org,
		Recipient:      iss.Recipient(),
		CredentialType: iss.ConfigID(),
		Services:       credentials.DefaultServiceProviderServices,
	}, nil
}

// Consent records the chosen services.
func (s *Service) Consent(iss *issuance.Issuance, services []string) error {
	return iss.Consent(services)
}

// Issue mints the credential for the given holder and returns it verbatim.
func (s *Service) Issue(ctx context.Context, iss *issuance.Issuance, holderDID string) (json.RawMessage, error) {
	issuerDID, err := s.resolveIssuerDID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer DID: %w", err)
	}
	cred := credentials.BuildServiceProviderCredential(issuerDID, credentials.ServiceProvider{
		DID:       holderDID,
		LegalName: iss.Organization().LegalName,
		Services:  iss.Services(),
	}, s.cfg.CredentialValidity, s.now())

	vc, err := s.minter.Mint(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("mint credential: %w", err)
	}
	if err := iss.Issue(holderDID); err != nil {
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
