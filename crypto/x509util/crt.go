package x509util

import (
	//nolint:gosec // sha1 is being used to calculate an identifier, not a key.
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/fingerprint"
	"go.step.sm/cli-utils/errs"
)

// Fingerprint returns the SHA-256 fingerprint of the certificate.
func Fingerprint(cert *x509.Certificate) string {
	h, _ := EncodedFingerprint(cert, HexFingerprint, false, false)
	return h
}

// FingerprintEncoding represents the fingerprint encoding type.
type FingerprintEncoding int

const (
	// HexFingerprint represents hex encoding of fingerprint.
	HexFingerprint = FingerprintEncoding(fingerprint.HexFingerprint)
	// Base64Fingerprint represents base64 encoding of fingerprint.
	Base64Fingerprint = FingerprintEncoding(fingerprint.Base64StdFingerprint)
	// Base64URLFingerprint represents base64URL encoding of fingerprint.
	Base64URLFingerprint = FingerprintEncoding(fingerprint.Base64URLFingerprint)
	// Base64RawURLFingerprint represents base64Raw encoding of fingerprint.
	Base64RawURLFingerprint = FingerprintEncoding(fingerprint.Base64RawURLFingerprint)
	// Base64RawStdFingerprint represents base64Raw encoding of fingerprint.
	Base64RawStdFingerprint = FingerprintEncoding(fingerprint.Base64RawStdFingerprint)
	// EmojiFingerprint represents emoji encoding of fingerprint.
	EmojiFingerprint = FingerprintEncoding(fingerprint.EmojiFingerprint)
)

// EncodedFingerprint returns an encoded fingerprint of the certificate.
// Defaults to hex encoding and SHA-256.
func EncodedFingerprint(cert *x509.Certificate, encoding FingerprintEncoding,
	sha1Mode bool, insecure bool) (string, error) {
	if sha1Mode {
		if !insecure {
			return "", errors.New("sha1 requires '--insecure' flag")
		}
		//nolint:gosec // sha1 is being used to calculate an identifier, not a key.
		sum := sha1.Sum(cert.Raw)
		return fingerprint.Fingerprint(sum[:], fingerprint.WithEncoding(fingerprint.Encoding(encoding))), nil
	}
	sum := sha256.Sum256(cert.Raw)
	return fingerprint.Fingerprint(sum[:], fingerprint.WithEncoding(fingerprint.Encoding(encoding))), nil
}

// SplitSANs splits a slice of Subject Alternative Names into slices of
// IP Addresses and DNS Names. If an element is not an IP address, then it
// is bucketed as a DNS Name.
func SplitSANs(sans []string) (dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) {
	dnsNames = []string{}
	ips = []net.IP{}
	emails = []string{}
	uris = []*url.URL{}
	if sans == nil {
		return
	}

	for _, san := range sans {
		//nolint:gocritic // avoid ifelse -> switch statement linter suggestion
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else if u, err := url.Parse(san); err == nil && u.Scheme != "" {
			uris = append(uris, u)
		} else if strings.Contains(san, "@") {
			emails = append(emails, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	return
}

// ReadCertPool loads a certificate pool from disk.
// *path*: a file, a directory, or a comma-separated list of files.
func ReadCertPool(path string) (*x509.CertPool, error) {
	info, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "os.Stat %s failed", path)
	}

	var (
		files []string
		pool  = x509.NewCertPool()
	)
	if info != nil && info.IsDir() {
		finfos, err := os.ReadDir(path)
		if err != nil {
			return nil, errs.FileError(err, path)
		}
		for _, finfo := range finfos {
			files = append(files, filepath.Join(path, finfo.Name()))
		}
	} else {
		files = strings.Split(path, ",")
		for i := range files {
			files[i] = strings.TrimSpace(files[i])
		}
	}

	var pems []byte
	for _, f := range files {
		bytes, err := os.ReadFile(f)
		if err != nil {
			return nil, errs.FileError(err, f)
		}
		for len(bytes) > 0 {
			var block *pem.Block
			block, bytes = pem.Decode(bytes)
			if block == nil {
				// TODO: at a higher log level we should log the file we could not find.
				break
			}
			// Ignore PEM blocks that are not CERTIFICATEs.
			if block.Type != "CERTIFICATE" {
				continue
			}
			pems = append(pems, pem.EncodeToMemory(block)...)
		}
	}
	if ok := pool.AppendCertsFromPEM(pems); !ok {
		return nil, errors.Errorf("error loading Root certificates")
	}
	return pool, nil
}
