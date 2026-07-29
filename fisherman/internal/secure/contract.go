// Package secure implements the explicit Snosi schema-1 secure install path.
package secure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	Schema              = 1
	MinimumESPBytes     = uint64(2147483648)
	MinimumDiskBytes    = uint64(32212254720)
	CapabilityLabel     = "io.snosi.bootc.secureboot-capable"
	CapabilityValue     = "true"
	EncryptedRootMapper = "root"
)

// Contract is the schema-1 rootfs contract at /usr/lib/snosi/bootc-secure.json.
type Contract struct {
	Schema              int       `json:"schema"`
	MOKCertificate      string    `json:"mok_certificate"`
	PCRPublicKey        string    `json:"pcr_public_key"`
	EncryptedRootMapper string    `json:"encrypted_root_mapper"`
	SystemdSuite        string    `json:"systemd_suite"`
	Assembly            Assembly  `json:"assembly"`
	Installer           Installer `json:"installer"`
}

// LoadInstalledContract reads and validates the immutable deployed contract.
func LoadInstalledContract(targetRoot string) (*Contract, error) {
	data, err := os.ReadFile(filepath.Join(targetRoot, "usr/lib/snosi/bootc-secure.json"))
	if err != nil {
		return nil, fmt.Errorf("reading installed secure contract: %w", err)
	}
	return ParseContract(data)
}

type Assembly struct {
	Compatibility        string `json:"compatibility"`
	BootcVersion         string `json:"bootc_version"`
	StorageDigestCommand string `json:"storage_digest_command"`
	UKI                  string `json:"ukify"`
}

type Installer struct {
	MinimumVersions   MinimumVersions   `json:"minimum_versions"`
	MinimumCapacities MinimumCapacities `json:"minimum_capacities"`
	OCI               OCI               `json:"oci"`
	Storage           Storage           `json:"storage"`
	BootcInstall      BootcInstall      `json:"bootc_install"`
	SecureBoot        SecureBoot        `json:"secure_boot"`
	TPM               TPM               `json:"tpm"`
}

type MinimumVersions struct {
	Bootc   string `json:"bootc"`
	Cosign  string `json:"cosign"`
	Systemd string `json:"systemd"`
}
type MinimumCapacities struct {
	ESPBytes        uint64 `json:"esp_bytes"`
	TargetDiskBytes uint64 `json:"target_disk_bytes"`
}
type OCI struct {
	CapabilityLabel string `json:"capability_label"`
	CapabilityValue string `json:"capability_value"`
	Policy          string `json:"policy"`
	SignedIdentity  string `json:"signed_identity"`
}
type Storage struct {
	ESPPartitionType  string `json:"esp_partition_type"`
	RootPartitionType string `json:"root_partition_type"`
	RootFilesystem    string `json:"root_filesystem"`
}
type BootcInstall struct {
	ComposefsBackend bool   `json:"composefs_backend"`
	Bootloader       string `json:"bootloader"`
	RootMountSpec    string `json:"root_mount_spec"`
	Type             string `json:"type"`
	ForbidKargs      bool   `json:"forbid_kargs"`
}
type SecureBoot struct {
	Shim        string `json:"shim"`
	SecondStage string `json:"second_stage"`
	MOKManager  string `json:"mok_manager"`
}
type TPM struct {
	PCRPublicKey               string `json:"pcr_public_key"`
	PCRPublicKeySource         string `json:"pcr_public_key_source"`
	PCRs                       string `json:"pcrs"`
	PublicKeyPCRs              string `json:"public_key_pcrs"`
	PCRLock                    string `json:"pcrlock"`
	Device                     string `json:"device"`
	UnlockKeyFileRequired      bool   `json:"unlock_key_file_required"`
	RecoveryPassphraseRequired bool   `json:"recovery_passphrase_required"`
}

// ParseContract accepts only the supported schema-1 secure-install contract.
func ParseContract(data []byte) (*Contract, error) {
	var contract Contract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return nil, fmt.Errorf("parsing secure contract: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("parsing secure contract: trailing JSON data")
	}
	if err := contract.Validate(); err != nil {
		return nil, err
	}
	return &contract, nil
}

// Validate rejects absent required fields and unsupported schema-1 values.
func (c Contract) Validate() error {
	if c.Schema != Schema || c.EncryptedRootMapper != EncryptedRootMapper || c.SystemdSuite != "forky" ||
		c.MOKCertificate == "" || c.PCRPublicKey == "" {
		return fmt.Errorf("secure contract has unsupported schema or root requirements")
	}
	if c.Assembly.Compatibility != "bootc-1.16.3-storage-digest-v1" || c.Assembly.BootcVersion != "1.16.3" ||
		c.Assembly.StorageDigestCommand != "bootc container compute-composefs-digest-from-storage" || c.Assembly.UKI != "direct-two-pass" {
		return fmt.Errorf("secure contract has unsupported assembly compatibility")
	}
	if c.Installer.MinimumVersions.Bootc != "1.16.3" || c.Installer.MinimumVersions.Cosign != "2.6.1" ||
		c.Installer.MinimumVersions.Systemd != "261.1-3" || c.Installer.MinimumCapacities.ESPBytes != MinimumESPBytes ||
		c.Installer.MinimumCapacities.TargetDiskBytes != MinimumDiskBytes {
		return fmt.Errorf("secure contract has unsupported installer version or capacity requirements")
	}
	if c.Installer.OCI.CapabilityLabel != CapabilityLabel || c.Installer.OCI.CapabilityValue != CapabilityValue ||
		c.Installer.OCI.Policy != "/etc/containers/policy.json" || c.Installer.OCI.SignedIdentity != "matchRepository" ||
		c.Installer.Storage.ESPPartitionType != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
		c.Installer.Storage.RootPartitionType != "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" ||
		c.Installer.Storage.RootFilesystem != "btrfs" || c.Installer.BootcInstall.Bootloader != "systemd" ||
		!c.Installer.BootcInstall.ComposefsBackend || c.Installer.BootcInstall.RootMountSpec != "" ||
		c.Installer.BootcInstall.Type != "uki-type-2" || !c.Installer.BootcInstall.ForbidKargs ||
		c.Installer.SecureBoot.Shim != "debian" || c.Installer.SecureBoot.SecondStage != "mok-signed-systemd-boot" ||
		c.Installer.SecureBoot.MOKManager != "MokManager" {
		return fmt.Errorf("secure contract has unsupported install requirements")
	}
	if c.Installer.TPM.PCRPublicKey != c.PCRPublicKey || c.Installer.TPM.PCRPublicKeySource != "installed-uki-pcrpkey" ||
		c.Installer.TPM.PCRs != "" || c.Installer.TPM.PublicKeyPCRs != "11" || c.Installer.TPM.PCRLock != "" ||
		c.Installer.TPM.Device != "auto" || !c.Installer.TPM.UnlockKeyFileRequired || !c.Installer.TPM.RecoveryPassphraseRequired {
		return fmt.Errorf("secure contract has unsupported TPM requirements")
	}
	return nil
}
