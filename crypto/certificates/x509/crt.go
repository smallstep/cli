package x509

import (
	realx509 "crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/pkg/x509"
)

// WriteCertificate encodes a x509 Certificate to a file on disk in PEM format.
func WriteCertificate(crt []byte, out string) error {
	if crt == nil {
		return errors.Errorf("crt cannot be nil")
	}
	certOut, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		os.FileMode(0644))
	if err != nil {
		return errs.FileError(err, out)
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	if err != nil {
		return errors.Wrapf(err,
			"pem encode '%s' failed", out)
	}
	certOut.Close()
	return nil
}

// LoadCertificate load a certificate.
func LoadCertificate(crtPath string) (*x509.Certificate, *pem.Block, error) {
	publicBytes, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return nil, nil, errs.FileError(err, crtPath)
	}
	publicPEM, _ := pem.Decode(publicBytes)
	if publicPEM == nil {
		return nil, nil, errors.Errorf("error decoding certificate file %s", crtPath)
	}
	crt, err := x509.ParseCertificate(publicPEM.Bytes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error parsing x509 certificate file %s", crtPath)
	}

	return crt, publicPEM, nil
}

// ReadCertPool loads a certificate pool from disk.
func ReadCertPool(path string) (*realx509.CertPool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var (
		files []string
		pool  = realx509.NewCertPool()
	)
	if info.IsDir() {
		finfos, err := ioutil.ReadDir(path)
		if err != nil {
			return nil, errs.FileError(err, path)
		}
		for _, finfo := range finfos {
			files = append(files, filepath.Join(path, finfo.Name()))
		}
	} else {
		files = strings.Split(path, ",")
	}

	var pems []byte
	for _, f := range files {
		bytes, err := ioutil.ReadFile(f)
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
