package cryptoutil

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExitErrorRedactsCommandLine(t *testing.T) {
	cmd := exec.Command("step-kms-plugin", "sign", "--format", "base64",
		"--kms", "yubikey:serial=7654321;pin-value=123456;management-key=010203040506070801020304050607080102030405060708",
		"yubikey:slot-id=9c;pin-value=positional-pin")
	ee := &exec.ExitError{
		ProcessState: &os.ProcessState{},
		Stderr:       []byte("Error: command failed: smart card error 6982: security status not satisfied"),
	}

	err := exitError(cmd, ee)
	require.Error(t, err)

	s := err.Error()
	assert.NotContains(t, s, "123456")
	assert.NotContains(t, s, "010203040506070801020304050607080102030405060708")
	// A secret can appear in a positional argument too: --attestation-uri is
	// passed as both the --kms value and the positional key argument.
	assert.NotContains(t, s, "positional-pin")
	assert.Contains(t, s, "pin-value=REDACTED")
	assert.Contains(t, s, "management-key=REDACTED")
	assert.Contains(t, s, "serial=7654321")
	assert.Contains(t, s, "slot-id=9c")
	assert.Contains(t, s, "smart card error 6982")
}

func TestExitErrorRedactsStderr(t *testing.T) {
	cmd := exec.Command("step-kms-plugin", "attest",
		"--kms", "yubikey:serial=1;pin-value=secret123", "yubikey:slot-id=9c")
	ee := &exec.ExitError{
		ProcessState: &os.ProcessState{},
		Stderr:       []byte("Error: yubikey:serial=1;pin-value=secret123 does not implement Attester"),
	}

	err := exitError(cmd, ee)
	require.Error(t, err)

	s := err.Error()
	assert.NotContains(t, s, "secret123")
	assert.Contains(t, s, "does not implement Attester")
}

func TestExitErrorRedactsWrappedError(t *testing.T) {
	cmd := exec.Command("step-kms-plugin", "key",
		"--kms", "pkcs11:token=smallstep?pin-value=badger", "pkcs11:id=7777")
	sentinel := errors.New("something went wrong")

	err := exitError(cmd, sentinel)
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)

	s := err.Error()
	assert.NotContains(t, s, "badger")
	assert.Contains(t, s, "pin-value=REDACTED")
	assert.Contains(t, s, "token=smallstep")
}

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"yubikey pin-value mid-uri", "yubikey:serial=123;pin-value=secret;slot-id=9c", "yubikey:serial=123;pin-value=REDACTED;slot-id=9c"},
		{"yubikey management-key", "yubikey:management-key=010203;pin-value=abc", "yubikey:management-key=REDACTED;pin-value=REDACTED"},
		{"pkcs11 query attribute", "pkcs11:token=step?pin-value=pass&max-sessions=2", "pkcs11:token=step?pin-value=REDACTED&max-sessions=2"},
		{"azurekms client-secret", "azurekms:name=k;vault=v?client-id=id&client-secret=hunter2&tenant-id=t", "azurekms:name=k;vault=v?client-id=id&client-secret=REDACTED&tenant-id=t"},
		{"case-insensitive key", "yubikey:PIN-VALUE=abc", "yubikey:PIN-VALUE=REDACTED"},
		{"value at end of string", "yubikey:serial=1;pin-value=xyz", "yubikey:serial=1;pin-value=REDACTED"},
		{"empty value", "yubikey:pin-value=;slot-id=9a", "yubikey:pin-value=REDACTED;slot-id=9a"},
		{"value containing equals and percent", "yubikey:pin-value=a=b%20c;slot-id=9a", "yubikey:pin-value=REDACTED;slot-id=9a"},
		{"value with leading single quote", "yubikey:pin-value='q';slot-id=9c", "yubikey:pin-value=REDACTED;slot-id=9c"},
		{"value with embedded single quote", "pkcs11:token=step?pin-value=my'pin&max-sessions=2", "pkcs11:token=step?pin-value=REDACTED&max-sessions=2"},
		{"pin-source is a path, not a secret", "yubikey:pin-source=/etc/pin.txt;management-key-source=/etc/mk.txt", "yubikey:pin-source=/etc/pin.txt;management-key-source=/etc/mk.txt"},
		{"uri quoted inside prose", `error parsing "yubikey:serial=1;pin-value=abc": invalid uri`, `error parsing "yubikey:serial=1;pin-value=REDACTED": invalid uri`},
		{"multiple uris in one string", "--kms yubikey:pin-value=aaa yubikey:slot-id=9c;pin-value=bbb", "--kms yubikey:pin-value=REDACTED yubikey:slot-id=9c;pin-value=REDACTED"},
		{"no secrets", "tpmkms:name=my-key;device=/dev/tpmrm0", "tpmkms:name=my-key;device=/dev/tpmrm0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, redactSecrets(tt.in))
		})
	}
}
