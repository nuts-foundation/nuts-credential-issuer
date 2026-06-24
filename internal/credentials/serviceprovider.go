// Package credentials builds the credentials this issuer can mint.
//
// v1 builds exactly one type, the ServiceProviderCredential, per its definition
// in the nl-generic-functions IG:
// https://build.fhir.org/ig/nuts-foundation/nl-generic-functions-ig/credential-ServiceProviderCredential.html
//
// It is kept as a self-contained unit so a second credential type can be added
// later without generalising into a runtime-configurable registry.
package credentials

import "time"

// ServiceProviderCredentialType is the credential type and the OpenID4VCI
// credential configuration id this issuer advertises.
const ServiceProviderCredentialType = "ServiceProviderCredential"

// serviceProviderContext is the JSON-LD @context of the ServiceProviderCredential.
// It is intrinsic to the credential type. The second entry is the GIS context
// defining ServiceProvider, name and services; its host is still a placeholder
// (see lspxnuts-pilots #6/#7) and the issuing Nuts node must map it to the GIS
// JSON-LD context document.
var serviceProviderContext = []string{
	"https://www.w3.org/2018/credentials/v1",
	"http://gis-nl.example/",
}

// DefaultServiceProviderServices are the agreement-framework services asserted in
// the credential by default. They prefill the (editable) consent screen.
var DefaultServiceProviderServices = []string{"gbc-client"}

// ServiceProvider describes the subject of a ServiceProviderCredential.
type ServiceProvider struct {
	// DID is the service provider's did:web. It comes from the validated
	// OpenID4VCI request proof and becomes credentialSubject.id.
	DID string
	// LegalName is the service provider's legal name, from authentication.
	LegalName string
	// Services are the asserted services. When empty the defaults are used.
	Services []string
}

// BuildServiceProviderCredential assembles a ServiceProviderCredential. The
// @context is intrinsic to the credential type; services default to
// DefaultServiceProviderServices when none are given.
func BuildServiceProviderCredential(issuerDID string, sp ServiceProvider, validity time.Duration, now time.Time) Credential {
	services := sp.Services
	if len(services) == 0 {
		services = DefaultServiceProviderServices
	}
	return Credential{
		Context:   serviceProviderContext,
		Type:      []string{"VerifiableCredential", ServiceProviderCredentialType},
		IssuerDID: issuerDID,
		Subject: map[string]any{
			"id":       sp.DID,
			"@type":    "ServiceProvider",
			"name":     sp.LegalName,
			"services": services,
		},
		ExpirationDate: now.Add(validity).UTC().Format(time.RFC3339),
		Format:         "jwt_vc",
	}
}
