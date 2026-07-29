package secure

import (
	"fmt"
	"os"

	"github.com/tuna-os/fisherman/internal/progress"
	"github.com/tuna-os/fisherman/internal/runner"
)

// EnrollTPM verifies the external recovery credential and enrolls exactly the
// schema-1 signed-PCR-11 policy against the installed UKI key.
func EnrollTPM(recoveryKeyFile, installedPCRKey, backingDevice string) error {
	if err := AuthenticateRecovery(recoveryKeyFile, backingDevice); err != nil {
		return err
	}
	if err := runner.Run("systemd-cryptenroll",
		"--unlock-key-file="+recoveryKeyFile,
		"--tpm2-device=auto",
		"--tpm2-pcrs=",
		"--tpm2-public-key="+installedPCRKey,
		"--tpm2-public-key-pcrs=11",
		"--tpm2-pcrlock=",
		backingDevice); err != nil {
		return fmt.Errorf("enrolling signed-PCR-11 TPM token: %w", err)
	}
	progress.Secure("tpm_enrollment", "staged")
	return nil
}

// AuthenticateRecovery proves the operator supplied the installed root
// recovery credential without opening a second mapper.
func AuthenticateRecovery(recoveryKeyFile, backingDevice string) error {
	if err := ValidatePrivateRegularFile(recoveryKeyFile); err != nil {
		return fmt.Errorf("validating recovery credential file: %w", err)
	}
	if err := runner.Run("cryptsetup", "open", "--test-passphrase", "--key-file", recoveryKeyFile, backingDevice); err != nil {
		return fmt.Errorf("verifying recovery credential: %w", err)
	}
	return nil
}

// EnrollTPMBytes materializes the installed UKI public key in a mode-0600
// temporary file only for systemd-cryptenroll, then removes it.
func EnrollTPMBytes(recoveryKeyFile string, installedPCRKey []byte, backingDevice string) error {
	f, err := os.CreateTemp("", "fisherman-installed-pcrpkey-*")
	if err != nil {
		return fmt.Errorf("creating installed PCR key file: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("protecting installed PCR key file: %w", err)
	}
	if _, err := f.Write(installedPCRKey); err != nil {
		f.Close()
		return fmt.Errorf("writing installed PCR key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing installed PCR key file: %w", err)
	}
	return EnrollTPM(recoveryKeyFile, name, backingDevice)
}

// StageMOK stages the public MOK certificate noninteractively. mokutil exposes
// the password on its command line for --generate-hash; that upstream
// limitation cannot be avoided, so Fisherman neither logs nor persists it.
func StageMOK(certificate, mokPasswordFile string) error {
	if err := ValidatePrivateRegularFile(mokPasswordFile); err != nil {
		return fmt.Errorf("validating MOK password file: %w", err)
	}
	password, err := os.ReadFile(mokPasswordFile)
	if err != nil {
		return fmt.Errorf("reading MOK password file: %w", err)
	}
	if err := validateMOKPassword(password); err != nil {
		return err
	}
	der, err := os.CreateTemp("", "fisherman-mok-certificate-*")
	if err != nil {
		return fmt.Errorf("creating MOK DER file: %w", err)
	}
	derPath := der.Name()
	defer os.Remove(derPath)
	if err := der.Chmod(0o600); err != nil {
		der.Close()
		return fmt.Errorf("protecting MOK DER file: %w", err)
	}
	if err := der.Close(); err != nil {
		return fmt.Errorf("closing MOK DER file: %w", err)
	}
	if err := runner.Run("openssl", "x509", "-in", certificate, "-outform", "DER", "-out", derPath); err != nil {
		return fmt.Errorf("converting MOK certificate to DER: %w", err)
	}
	hash, err := runner.Output("mokutil", "--generate-hash="+string(password))
	if err != nil {
		return fmt.Errorf("generating MOK password hash: %w", err)
	}
	hashFile, err := os.CreateTemp("", "fisherman-mok-hash-*")
	if err != nil {
		return fmt.Errorf("creating MOK hash file: %w", err)
	}
	hashPath := hashFile.Name()
	defer os.Remove(hashPath)
	if err := hashFile.Chmod(0o600); err != nil {
		hashFile.Close()
		return fmt.Errorf("protecting MOK hash file: %w", err)
	}
	if _, err := hashFile.Write(hash); err != nil {
		hashFile.Close()
		return fmt.Errorf("writing MOK hash file: %w", err)
	}
	if err := hashFile.Close(); err != nil {
		return fmt.Errorf("closing MOK hash file: %w", err)
	}
	if err := runner.Run("mokutil", "--import", derPath, "--hash-file="+hashPath); err != nil {
		return fmt.Errorf("staging MOK enrollment: %w", err)
	}
	progress.Secure("mok_enrollment", "staged")
	return nil
}

func validateMOKPassword(password []byte) error {
	if len(password) < 8 || len(password) > 16 {
		return fmt.Errorf("MOK password must be 8 to 16 bytes")
	}
	for _, b := range password {
		if b == '\n' || b == '\r' || b < 0x21 || b > 0x7e {
			return fmt.Errorf("MOK password must contain only printable non-whitespace ASCII bytes")
		}
	}
	return nil
}
