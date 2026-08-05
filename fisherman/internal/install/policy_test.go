package install

import (
	"encoding/json"
	"os"
	"testing"
)

// The staged policy must be NARROWER than a hardened image's, not broader: it
// exists so bootc can open the local OCI layout fisherman exported, and must
// not become a way to accept an unverified registry pull.
func TestWriteLocalTransportPolicyRejectsByDefaultAndAllowsOnlyLocalTransports(t *testing.T) {
	dir := t.TempDir()
	path, err := writeLocalTransportPolicy(dir)
	if err != nil {
		t.Fatalf("writeLocalTransportPolicy: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Default    []map[string]string                       `json:"default"`
		Transports map[string]map[string][]map[string]string `json:"transports"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatalf("staged policy is not valid JSON: %v\n%s", err, raw)
	}
	if len(policy.Default) != 1 || policy.Default[0]["type"] != "reject" {
		t.Fatalf("default must be reject, got %v", policy.Default)
	}
	for _, transport := range []string{"oci", "containers-storage"} {
		scope, ok := policy.Transports[transport]
		if !ok || len(scope[""]) != 1 || scope[""][0]["type"] != "insecureAcceptAnything" {
			t.Fatalf("%s transport must accept the empty scope, got %v", transport, policy.Transports[transport])
		}
	}
	// The whole point: a registry pull must still be refused by this policy.
	if _, ok := policy.Transports["docker"]; ok {
		t.Fatal("staged policy must not grant the docker transport")
	}
}
