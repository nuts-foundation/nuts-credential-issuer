package issuer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/credentials"
	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

// configID is the single credential_configuration_id this issuer offers. It is
// hardcoded, like the credential it maps to.
const configID = credentials.ServiceProviderCredentialType

// Config holds the issuer's non-port settings.
type Config struct {
	// IssuerSubject is the Nuts subject whose did:web the credential is issued from.
	IssuerSubject string
}

// Service orchestrates the issuance use-cases over the domain and the ports. It
// is stateless: the inbound adapter owns the in-flight sessions and passes the
// issuance aggregate into each step.
type Service struct {
	minter   Minter
	subjects SubjectResolver
	now      func() time.Time
	cfg      Config

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
func (s *Service) CredentialType() string { return configID }

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
	if requested == "" || requested == configID {
		return configID, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedCredential, requested)
}

// Authenticate records the authenticated organisation and returns the consent
// details to present.
func (s *Service) Authenticate(iss *issuance.Issuance, org issuance.Organization) (ConsentDetails, error) {
	if err := iss.Authenticate(org); err != nil {
		return ConsentDetails{}, err
	}
	snap := iss.Snapshot()
	return ConsentDetails{
		Organization:   snap.Organization,
		Recipient:      snap.Recipient,
		CredentialType: snap.ConfigID,
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
	snap := iss.Snapshot()
	cred := credentials.BuildServiceProviderCredential(issuerDID, credentials.ServiceProvider{
		DID:       holderDID,
		LegalName: snap.Organization.LegalName,
		Services:  snap.Services,
	}, s.now())

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
// Resolving concurrently more than once is harmless (the result is the same), so
// no locking is used.
func (s *Service) resolveIssuerDID(ctx context.Context) (string, error) {
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
