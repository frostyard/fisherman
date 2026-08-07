package secure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The fifteen keys docs/bootc-secure-install-contract.md requires, and the two
// types it fixes. snosi's Task 9 check asserts exactly this, and a record that
// omits or misspells any of them fails a correct install -- which is what
// happened with mok_fingerprint, pcr_fingerprint, tpm_token_id, repository,
// and secure_capability being written as a label string instead of a boolean.
func TestProvenanceMatchesTheContractSchema(t *testing.T) {
	root := t.TempDir()
	if err := WriteProvenance(root, Provenance{
		OCIRef: "ghcr.io/frostyard/cayo@sha256:abc", TrackingRef: "ghcr.io/frostyard/cayo:latest",
		Repository: "ghcr.io/frostyard/cayo", Capability: true, Schema: 1,
		Assembly: "bootc-1.16.3-storage-digest-v1", Composefs: "deadbeef", UKIHash: "cafe",
		MOKHash: "mok", PCRHash: "pcr", ESPPartUUID: "part", LUKSUUID: "luks", TPMToken: "tok",
		Versions:  map[string]string{"fisherman": "0.2.16"},
		Validated: map[string]string{"bootc": "1.16.3", "cosign": "2.6.1", "systemd": "261.2-1"},
		Completed: "2026-08-07T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"oci_ref", "tracking_ref", "repository", "secure_capability", "contract_schema",
		"assembly_compatibility", "composefs_id", "uki_sha256", "mok_fingerprint",
		"pcr_fingerprint", "esp_partuuid", "luks_uuid", "tpm_token_id",
		"installer_versions", "validated_versions", "completed_at",
	} {
		if _, ok := record[key]; !ok {
			t.Errorf("contract key %q missing from the provenance record", key)
		}
	}
	// The contract fixes these two types explicitly.
	if got, ok := record["secure_capability"].(bool); !ok || !got {
		t.Errorf("secure_capability = %#v, want JSON boolean true", record["secure_capability"])
	}
	if got, ok := record["contract_schema"].(float64); !ok || got != 1 {
		t.Errorf("contract_schema = %#v, want JSON integer 1", record["contract_schema"])
	}
	// installer_versions carries what produced the system. Only fisherman is
	// knowable at install time -- the medium identifies neither the
	// bootc-installer Flatpak nor the Dakota ISO build.
	versions, ok := record["installer_versions"].(map[string]any)
	if !ok {
		t.Fatalf("installer_versions = %#v, want an object", record["installer_versions"])
	}
	if _, ok := versions["fisherman"]; !ok {
		t.Error("installer_versions.fisherman missing")
	}
	// validated_versions is the separate floor-policy audit trail: the
	// dependency versions detected on the medium, not the installer itself.
	validated, ok := record["validated_versions"].(map[string]any)
	if !ok {
		t.Fatalf("validated_versions = %#v, want an object", record["validated_versions"])
	}
	for _, dep := range []string{"bootc", "cosign", "systemd"} {
		if _, ok := validated[dep]; !ok {
			t.Errorf("validated_versions.%s missing", dep)
		}
	}
}
