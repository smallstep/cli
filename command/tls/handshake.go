package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/cryptoutil"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func handshakeCommand() cli.Command {
	return cli.Command{
		Name:        "handshake",
		Action:      cli.ActionFunc(handshakeAction),
		Usage:       `print handshake details`,
		UsageText:   `**step tls handshake** <url>`,
		Description: `**step tls handshake** displays detailed handshake information for a TLS connection.`,
		Flags: []cli.Flag{
			flags.ServerName,
			cli.StringFlag{
				Name: "tls",
				Usage: `Defines the TLS <version> in the handshake. By default it will use TLS 1.3 or TLS 1.2.
: The supported versions are **1.3**, **1.2**, **1.1**, and **1.0**.`,
			},
			cli.StringFlag{
				Name:  "cert",
				Usage: `The path to the <file> containing the client certificate to use.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: `The path to the <file> or KMS <uri> containing the certificate key to use.`,
			},
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) that will be used to verify the
authenticity of the remote server.

: <roots> is a case-sensitive string and may be one of:

    **file**
	:  Relative or full path to a file. All certificates in the file will be used for path validation.

    **list of files**
	:  Comma-separated list of relative or full file paths. Every PEM encoded certificate from each file will be used for path validation.

    **directory**
	:  Relative or full path to a directory. Every PEM encoded certificate from each file in the directory will be used for path validation.`,
			},

			cli.StringFlag{
				Name:  "password-file",
				Usage: "The path to the <file> containing the password to decrypt the private key.",
			},
			cli.BoolFlag{
				Name:  "chain",
				Usage: "Print only the chain of verified certificates.",
			},
			cli.BoolFlag{
				Name:  "peer",
				Usage: `Print only the peer certificates sent by the server.`,
			},
			cli.BoolFlag{
				Name: "insecure",
				Usage: `Use an insecure client to retrieve a remote peer certificate. Useful for
debugging invalid certificates remotely.`,
			},
		},
	}
}

func handshakeAction(c *cli.Context) error {
	if err := errs.NumberOfArguments(c, 1); err != nil {
		return err
	}

	var (
		addr         = c.Args().First()
		tlsVersion   = c.String("tls")
		roots        = c.String("roots")
		serverName   = c.String("servername")
		certFile     = c.String("cert")
		keyFile      = c.String("key")
		passwordFile = c.String("password-file")
		printChains  = c.Bool("chain")
		printPeer    = c.Bool("peer")
		insecure     = c.Bool("insecure")
		rootCAs      *x509.CertPool
		err          error
	)

	switch {
	case certFile != "" && keyFile == "":
		return errs.RequiredWithFlag(c, "cert", "key")
	case keyFile != "" && certFile == "":
		return errs.RequiredWithFlag(c, "key", "cert")
	}

	// Parse address
	if u, ok, err := utils.TrimURL(addr); err != nil {
		return err
	} else if ok {
		addr = u
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	// Load client TLS certificate
	var certificates []tls.Certificate
	if certFile != "" && keyFile != "" {
		opts := []pemutil.Options{}
		if passwordFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passwordFile))
		}
		crt, err := cryptoutil.LoadTLSCertificate(certFile, keyFile, opts...)
		if err != nil {
			return err
		}
		certificates = []tls.Certificate{crt}
	}

	// Get the list of roots used to validate the certificate.
	if roots != "" {
		rootCAs, err = x509util.ReadCertPool(roots)
		if err != nil {
			return fmt.Errorf("error loading root certificate pool from %q: %w", roots, err)
		}
	} else {
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("error loading the system cert pool: %w", err)
		}
	}

	// Get the tls version to use. Defaults to TLS 1.2+
	minVersion, maxVersion, err := getTLSVersions(tlsVersion)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		RootCAs:            rootCAs,
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
		Certificates:       certificates,
	}

	cs, err := tlsDialWithFallback(context.Background(), addr, tlsConfig)
	if err != nil {
		return err
	}

	// Print only the list of verified chains
	if printChains {
		if len(cs.VerifiedChains) == 0 {
			return errors.New("failed to build a chain of verified certificates")
		}
		for _, chain := range cs.VerifiedChains {
			for _, crt := range chain {
				fmt.Print(string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: crt.Raw,
				})))
			}
		}
		return nil
	}

	// Print only the peer certificates
	if printPeer {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("peer did not sent a certificate")
		}
		for _, crt := range cs.PeerCertificates {
			fmt.Print(string(pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: crt.Raw,
			})))
		}
		return nil
	}

	// Check if the certificate is valid
	var intermediates *x509.CertPool
	if len(cs.PeerCertificates) > 1 {
		intermediates = x509.NewCertPool()
		for _, crt := range cs.PeerCertificates[1:] {
			intermediates.AddCert(crt)
		}
	}
	_, verifyErr := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	connStateValue := reflect.ValueOf(cs)
	curveIDField := connStateValue.FieldByName("testingOnlyCurveID")

	fmt.Printf("Server Name:  %s\n", cs.ServerName)
	fmt.Printf("Version:      %s\n", tls.VersionName(cs.Version))
	fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	fmt.Printf("KEM:          %s\n", curveIDName(curveIDField.Uint()))
	fmt.Printf("Insecure:     %v\n", tlsConfig.InsecureSkipVerify)
	fmt.Printf("Verified:     %v\n", verifyErr == nil)

	return nil
}

func curveIDName(curveID uint64) string {
	switch tls.CurveID(curveID) {
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case tls.X25519:
		return "X25519"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	default:
		return "Unknown"
	}
}

func getTLSVersions(s string) (uint16, uint16, error) {
	switch s {
	case "":
		return tls.VersionTLS12, 0, nil
	case "1.3":
		return tls.VersionTLS13, tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, tls.VersionTLS12, nil
	case "1.1":
		return tls.VersionTLS11, tls.VersionTLS11, nil
	case "1.0":
		return tls.VersionTLS10, tls.VersionTLS10, nil
	default:
		return 0, 0, fmt.Errorf("unsupported TLS version %q", s)
	}
}

func tlsDialWithFallback(ctx context.Context, addr string, tlsConfig *tls.Config) (tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		if tlsConfig.InsecureSkipVerify {
			return tls.ConnectionState{}, fmt.Errorf("error connecting to %q: %w", addr, err)
		}
		tlsConfig.InsecureSkipVerify = true
		return tlsDialWithFallback(ctx, addr, tlsConfig)
	}
	defer conn.Close()
	return conn.ConnectionState(), conn.HandshakeContext(ctx)
}
