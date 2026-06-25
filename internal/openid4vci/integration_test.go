//go:build integration

// This integration test runs the full OpenID4VCI issuance flow against a real
// Nuts node started with testcontainers. It needs Docker and binds host ports
// 8080 and 8081 (stop the local `make up` stack first). Run with:
//
//	go test -tags integration -run TestIntegration ./internal/openid4vci/ -timeout 300s -v
package openid4vci_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// nodeURL is the node's public identity inside and outside the container. The
// port must equal the container's internal public port (8080) so that did:web
// (did:web:localhost%3A8080:...) resolves both inside the node and from the
// host-side issuer, which reaches the node via the published port.
const (
	nodeURL          = "http://localhost:8080"
	nodeInternalURL  = "http://localhost:8081"
	nodePublicPort   = "8080"
	nodeInternalPort = "8081"
)

func TestIntegration_IssueServiceProviderCredential(t *testing.T) {
	ctx := context.Background()
	startNode(t, ctx)

	createSubject(t, "issuer")
	createSubject(t, "wallet")
	walletDID := resolveDID(t, "wallet")

	// The node reaches the in-process issuer via host.docker.internal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	issuerBaseURL := fmt.Sprintf("http://host.docker.internal:%d", port)

	runIssuanceFlow(t, ln, nodeInternalURL, "wallet", walletDID, issuerBaseURL, "issuer")
}

// startNode boots the Nuts node container (acting as issuer signer + wallet),
// publishing its public (8080) and internal (8081) APIs on the same host ports.
func startNode(t *testing.T, ctx context.Context) {
	t.Helper()

	// Node config with the public url on localhost:8080 so did:web resolves from
	// the host-side issuer over the published port.
	cfgSrc, err := os.ReadFile(filepath.Join("..", "..", "deploy", "nuts", "nuts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.ReplaceAll(string(cfgSrc), "http://nutsnode:8080", nodeURL)
	cfgPath := filepath.Join(t.TempDir(), "nuts.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	contextPath, err := filepath.Abs(filepath.Join("..", "..", "deploy", "nuts", "contexts", "gis.jsonld"))
	if err != nil {
		t.Fatal(err)
	}

	req := testcontainers.ContainerRequest{
		Image: "nutsfoundation/nuts-node:project-gf-pilot",
		Env: map[string]string{
			"NUTS_CONFIGFILE": "/nuts/nuts.yaml",
			"NUTS_VERBOSITY":  "debug",
		},
		ExposedPorts: []string{nodePublicPort + "/tcp", nodeInternalPort + "/tcp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfgPath, ContainerFilePath: "/nuts/nuts.yaml", FileMode: 0o644},
			{HostFilePath: contextPath, ContainerFilePath: "/nuts/contexts/gis.jsonld", FileMode: 0o644},
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			anyIP := netip.MustParseAddr("0.0.0.0")
			hc.PortBindings = network.PortMap{
				network.MustParsePort(nodePublicPort + "/tcp"):   {{HostIP: anyIP, HostPort: nodePublicPort}},
				network.MustParsePort(nodeInternalPort + "/tcp"): {{HostIP: anyIP, HostPort: nodeInternalPort}},
			}
			// Lets the node reach the host-side issuer at host.docker.internal (Linux).
			hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
		},
		WaitingFor: wait.ForHTTP("/status").WithPort(nodeInternalPort + "/tcp").WithStartupTimeout(90 * time.Second),
	}
	node, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start nuts node: %v", err)
	}
	t.Cleanup(func() { _ = node.Terminate(context.Background()) })
}

func createSubject(t *testing.T, subject string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"subject": subject})
	resp, err := http.Post(nodeInternalURL+"/internal/vdr/v2/subject", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create subject %q: %v", subject, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("create subject %q: HTTP %d: %s", subject, resp.StatusCode, raw)
	}
}

func resolveDID(t *testing.T, subject string) string {
	t.Helper()
	resp, err := http.Get(nodeInternalURL + "/internal/vdr/v2/subject/" + subject)
	if err != nil {
		t.Fatalf("resolve subject %q: %v", subject, err)
	}
	defer resp.Body.Close()
	var dids []string
	if err := json.NewDecoder(resp.Body).Decode(&dids); err != nil || len(dids) == 0 {
		t.Fatalf("resolve subject %q: %v (%v)", subject, err, dids)
	}
	return dids[0]
}
