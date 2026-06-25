# nuts-credential-issuer

An [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
issuer for the `ServiceProviderCredential`.

A wallet (a vendor's Nuts node) runs an OpenID4VCI Authorization Code flow against
this application. The application authenticates the user, validates the wallet's
credential-request proof, mints the credential via a **Nuts node**, and returns the
JWT VC over the credential endpoint. The application holds no signing keys — the
issuer DID's key lives in the Nuts node.

Implements #16 of `nuts-foundation/lspxnuts-pilots`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/.well-known/openid-credential-issuer` | Credential Issuer Metadata |
| GET | `/.well-known/oauth-authorization-server` | Authorization Server Metadata |
| GET | `/authorize` | Start authentication + consent |
| POST | `/login` | Login form submit (authenticator) |
| POST | `/consent` | Consent form submit → returns the authorization code |
| POST | `/token` | Token endpoint (Authorization Code + PKCE) |
| POST | `/nonce` | Nonce endpoint (`c_nonce` for the proof) |
| POST | `/credential` | Validate proof, mint via Nuts node, return the VC |

The `/credential` response is the OpenID4VCI 1.0 shape:

```json
{ "credentials": [ { "credential": "<JWT VC minted by the Nuts node>" } ] }
```

The credential request accepts both the OpenID4VCI 1.0 plural `proofs.jwt[]` and
the older singular `proof.jwt` shapes, since which the wallet sends depends on the
Nuts node version.

## Configuration

All configuration is via environment variables.

Config is loaded with [koanf](https://github.com/knadh/koanf).

All variables are namespaced with the `CIS_` (Credential ISsuer) prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `CIS_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `CIS_TITLE` | `Nuts Credential Issuer` | Issuer display name shown in the UI |
| `CIS_BASE_URL` | `http://localhost:8080` | Credential Issuer Identifier and base for the authorize/token/credential/nonce endpoints |
| `CIS_ISSUER_SUBJECT` | `issuer` | Nuts subject the issuer issues from; its `did:web` is resolved from the node at runtime. Create it in Nuts Admin |
| `CIS_NUTS_NODE_URL` | `http://localhost:8081` | Nuts node internal API base URL |
| `CIS_DEMO` | `false` | Enable the fake eHerkenning authenticator (required — no other authenticator exists yet). Also allows plain-HTTP `did:web` resolution |
| `CIS_DEMO_ORG_NAME` | `Voorbeeld Dienstverlener B.V.` | Default legal name in the (editable) demo login |
| `CIS_DEMO_ORG_IDENTIFIER` | `90000001` | Default KvK/identifier in the (editable) demo login |
| `CIS_BROWSER_CALLBACK_REWRITE` | *(none)* | `from=to` host rewrite for the wallet callback in the browser redirect, when the node's `NUTS_URL` is not browser-reachable (e.g. `nutsnode:8080=localhost:8080`) |

The credential validity is intrinsic to the credential type (1 year), not configurable.

The issuer DID is not configured directly: it is resolved from `CIS_ISSUER_SUBJECT`
via the Nuts node, so no DID or key material lives in the application. The
`@context` and `services` are intrinsic to the `ServiceProviderCredential` type
(`internal/credentials`), not configurable. The issuing Nuts node must map the GIS
`@context` to the GIS JSON-LD context document.

## Authentication is swappable

Authentication sits behind the `auth.Authenticator` interface: the authenticator
renders its own login UI (`Start`) and registers its own HTTP handlers
(`RegisterRoutes`), calling back into the issuer once the user is authenticated.
The demo ships a **fake eHerkenning** authenticator (`internal/auth/eherkenning`)
with an editable login form. It performs **no identity verification**; the issuer
refuses to start unless `DEMO=true`, so it can never be the default in a hosted
deployment. Real authentication can be added behind the same interface without
touching the OpenID4VCI core.

## Adding another credential type

Credential building is a self-contained unit (`internal/credentials`). A second
type can be added there without generalising into a runtime-configurable
registry — that is intentionally out of scope for v1.

## Local stack (Docker Compose)

Runs the issuer, a Nuts node (acting as both the issuer's signing node and the
vendor wallet), and Nuts Admin. Server-to-server calls use Docker service names;
the `make request` script rewrites those hosts to `localhost` for its own
host-side calls.

```sh
make up        # start node + admin + issuer
```

Then create two subjects in **Nuts Admin** (http://localhost:1305):

- `issuer` — the issuer signs `ServiceProviderCredential`s from this subject
- `wallet` — the vendor wallet that receives the credential

```sh
make request                    # headless: issue with the default demo organisation
make request ORG="Acme B.V."    # headless: issue asserting a different organisation
make demo                       # interactive: opens the login page in your browser
make logs                       # follow issuer + node logs
make down                       # stop everything
```

`make request` is the primary, fully self-contained flow. `make demo` opens a real
browser; after consent the wallet's callback points at the node's internal
hostname (`nutsnode`), so the browser must be able to resolve it. Add this line to
`/etc/hosts` first:

```
127.0.0.1 nutsnode
```

- `make demo` (`deploy/demo.sh`) starts an issuance and opens the issuer login
  page in your browser. You log in (the fake eHerkenning form is editable) and
  consent; the script waits for the credential and prints it.
- `make request` (`deploy/request-credential.sh`) drives the same flow headlessly
  (request-credential → demo login → consent → callback) and prints the
  `ServiceProviderCredential`.

The node advertises its OAuth callback at its internal hostname
(`NUTS_URL=http://nutsnode:8080`). For the browser flow, the issuer rewrites that
callback host to `localhost` when it renders the redirect
(`CIS_BROWSER_CALLBACK_REWRITE=nutsnode:8080=localhost:8080`); the original URL
is still used for the OAuth `/token` check.

## End-to-end test

`internal/openid4vci/e2e_test.go` drives the full flow against a real Nuts holder
node in-process. It is skipped unless the `E2E_*` environment is set; see the test
file for the required variables.
