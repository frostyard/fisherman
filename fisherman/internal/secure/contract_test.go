package secure_test

import (
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/secure"
)

const validContract = `{
  "schema": 1,
  "mok_certificate": "/usr/lib/snosi/mok.crt",
  "pcr_public_key": "/usr/lib/snosi/pcr-signing.pub",
  "encrypted_root_mapper": "root",
  "systemd_suite": "forky",
  "assembly": {"compatibility":"bootc-1.16.3-storage-digest-v1","bootc_version":"1.16.3","storage_digest_command":"bootc container compute-composefs-digest-from-storage","ukify":"direct-two-pass"},
  "installer": {
    "minimum_versions":{"bootc":"1.16.3","cosign":"2.6.1","systemd":"261.1-3"},
    "minimum_capacities":{"esp_bytes":2147483648,"target_disk_bytes":32212254720},
    "oci":{"capability_label":"io.snosi.bootc.secureboot-capable","capability_value":"true","policy":"/etc/containers/policy.json","signed_identity":"matchRepository"},
    "storage":{"esp_partition_type":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","root_partition_type":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709","root_filesystem":"btrfs"},
    "bootc_install":{"composefs_backend":true,"bootloader":"systemd","root_mount_spec":"","type":"uki-type-2","forbid_kargs":true},
    "secure_boot":{"shim":"debian","second_stage":"mok-signed-systemd-boot","mok_manager":"MokManager"},
    "tpm":{"pcr_public_key":"/usr/lib/snosi/pcr-signing.pub","pcr_public_key_source":"installed-uki-pcrpkey","pcrs":"","public_key_pcrs":"11","pcrlock":"","device":"auto","unlock_key_file_required":true,"recovery_passphrase_required":true}
  }
}`

func TestParseContractAcceptsOnlySchemaOneSecureCapabilities(t *testing.T) {
	contract, err := secure.ParseContract([]byte(validContract))
	if err != nil {
		t.Fatalf("ParseContract() error = %v", err)
	}
	if contract.Installer.MinimumCapacities.TargetDiskBytes != 32212254720 {
		t.Fatalf("target disk floor = %d", contract.Installer.MinimumCapacities.TargetDiskBytes)
	}

	for name, body := range map[string]string{
		"unknown schema":   strings.Replace(validContract, `"schema": 1`, `"schema": 2`, 1),
		"wrong mapper":     strings.Replace(validContract, `"encrypted_root_mapper": "root"`, `"encrypted_root_mapper": "other"`, 1),
		"wrong bootloader": strings.Replace(validContract, `"bootloader":"systemd"`, `"bootloader":"grub2"`, 1),
		"wrong pcr":        strings.Replace(validContract, `"public_key_pcrs":"11"`, `"public_key_pcrs":"7"`, 1),
		"unknown field":    strings.Replace(validContract, `"schema": 1`, `"schema": 1, "unexpected": true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := secure.ParseContract([]byte(body)); err == nil || !strings.Contains(err.Error(), "contract") {
				t.Fatalf("ParseContract() error = %v, want contract rejection", err)
			}
		})
	}
}
