package credentials

// Credential is a neutral representation of a verifiable credential to be minted.
// It carries no knowledge of any node's wire format; an outbound adapter (e.g.
// the Nuts client) maps it to the API it calls.
type Credential struct {
	// Context is the JSON-LD @context.
	Context []string
	// Type is the credential type array (e.g. ["VerifiableCredential", "..."]).
	Type []string
	// IssuerDID is the DID of the issuer.
	IssuerDID string
	// Subject is the credentialSubject.
	Subject map[string]any
	// ExpirationDate is RFC3339, or empty for no expiry.
	ExpirationDate string
	// Format is the proof format (e.g. "jwt_vc").
	Format string
	// Revocable adds a StatusList2021 credentialStatus so the credential can be
	// revoked after issuance (only valid for did:web issuers).
	Revocable bool
}
