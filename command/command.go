package command

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/fingerprint"
	"github.com/urfave/cli"
)

// FingerprintFormatFlag returns a flag for configuring the fingerprint format.
func FingerprintFormatFlag(defaultFmt string) cli.StringFlag {
	return cli.StringFlag{
		Name:  "format",
		Usage: `The <format> of the fingerprint, it must be "hex", "base64", "base64-url", "base64-raw", "base64-url-raw" or "emoji".`,
		Value: defaultFmt,
	}
}

// GetFingerprintEncoding gets the fingerprint encoding from the format flag.
func GetFingerprintEncoding(format string) (fingerprint.Encoding, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "hex", "":
		return fingerprint.HexFingerprint, nil
	case "base64":
		return fingerprint.Base64StdFingerprint, nil
	case "base64url", "base64-url":
		return fingerprint.Base64URLFingerprint, nil
	case "base64urlraw", "base64url-raw", "base64-url-raw":
		return fingerprint.Base64RawURLFingerprint, nil
	case "base64raw", "base64-raw":
		return fingerprint.Base64RawStdFingerprint, nil
	case "emoji", "emojisum":
		return fingerprint.EmojiFingerprint, nil
	default:
		return 0, errors.Errorf("error parsing fingerprint format: '%s' is not a valid fingerprint format", format)
	}
}
