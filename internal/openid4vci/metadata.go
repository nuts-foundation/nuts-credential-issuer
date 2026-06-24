package openid4vci

// proofSigningAlgs are the signature algorithms this issuer accepts on
// credential-request proofs.
var proofSigningAlgs = []string{"ES256", "EdDSA"}

// issuerMetadata builds the OpenID4VCI Credential Issuer Metadata document
// served at /.well-known/openid-credential-issuer.
func issuerMetadata(baseURL, credentialConfigID string) map[string]any {
	return map[string]any{
		"credential_issuer":     baseURL,
		"credential_endpoint":   baseURL + "/credential",
		"nonce_endpoint":        baseURL + "/nonce",
		"authorization_servers": []string{baseURL},
		"credential_configurations_supported": map[string]any{
			credentialConfigID: map[string]any{
				"format": "jwt_vc",
				"credential_definition": map[string]any{
					"type": []string{"VerifiableCredential", credentialConfigID},
				},
				"cryptographic_binding_methods_supported": []string{"did:web"},
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{
						"proof_signing_alg_values_supported": proofSigningAlgs,
					},
				},
			},
		},
	}
}

// authServerMetadata builds the OAuth 2.0 Authorization Server Metadata document
// served at /.well-known/oauth-authorization-server. The authorization_endpoint
// is the one URL a browser is redirected to, so it may differ from baseURL (the
// server-to-server base) in a containerised setup.
func authServerMetadata(baseURL, authorizationEndpoint string) map[string]any {
	return map[string]any{
		"issuer":                           baseURL,
		"authorization_endpoint":           authorizationEndpoint,
		"token_endpoint":                   baseURL + "/token",
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code"},
		"code_challenge_methods_supported": []string{"S256"},
	}
}
