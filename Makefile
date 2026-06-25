.PHONY: up request demo down logs

# Start the node, Nuts Admin and the issuer.
#
# Then, one-time, create two subjects in Nuts Admin (http://localhost:1305):
#   - "issuer"  (the issuer signs ServiceProviderCredentials from this subject)
#   - "wallet"  (the vendor wallet that receives the credential)
up:
	docker compose up -d --build
	@echo
	@echo "Issuer:     http://localhost:8088"
	@echo "Nuts Admin: http://localhost:1305"
	@echo
	@echo "Next: in Nuts Admin create subjects 'issuer' and 'wallet', then run 'make request'."

# Run the OpenID4VCI flow headlessly and fetch the credential.
# Optionally override the asserted organisation: make request ORG="Acme B.V."
request:
	./deploy/request-credential.sh $(if $(ORG),"$(ORG)",)

# Interactive demo: opens the issuer login page in your browser, then waits for
# the credential to land in the wallet.
demo:
	./deploy/demo.sh

down:
	docker compose down

logs:
	docker compose logs -f issuer nutsnode
