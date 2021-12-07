package fileserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/pkg/errors"

	"github.com/smallstep/cli/utils"
	"go.step.sm/cli-utils/errs"

	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
)

func init() {
	cmd := cli.Command{
		Name:   "fileserver",
		Hidden: true,
		Action: command.ActionFunc(fileServerAction),
		Usage:  "start an HTTP(S) server serving the contents of a path",
		UsageText: `step fileserver <dir>
[**--address**=<address>] [**--cert**=<file>] [**--key**=<file>] [**--roots**=<file>]`,
		Description: `**step fileserver** command starts an HTTP(S) server serving the contents of a file
system.

This command is experimental and only intended for test purposes.

## POSITIONAL ARGUMENTS

<dir>
: The directory used as root for the HTTP file server.

## EXAMPLES

Start an HTTP file server on port 8080.
'''
$ step fileserver --address :8080 /path/to/web-root
'''

Start an HTTPS file server on 127.0.0.1:8443.
'''
$ step ca certificate 127.0.0.1 localhost.crt localhost.key
...
$ step fileserver --address 127.0.0.1:8443 \
  --cert localhost.crt --key localhost.key /path/to/web-root
'''

Start an HTTPS file server on a random port and require client certificates.
'''
$ step fileserver --cert localhost.crt --key localhost.key \
  --roots $(step path)/certs/root_ca.crt /path/to/web-root
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "address",
				Usage: "The TCP <address> to listen on (e.g. \":8443\").",
				Value: ":0",
			},
			cli.StringFlag{
				Name:  "cert",
				Usage: `The <file> containing the TLS certificate to use.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: `The <file> containing the key corresponding to the certificate.`,
			},
			cli.StringFlag{
				Name:  "roots",
				Usage: "The <file> containing the root certificate(s) that will be used to verify the client certificates.",
			},
		},
	}
	command.Register(cmd)
}

func fileServerAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	root := ctx.Args().First()
	f, err := os.Stat(root)
	if err != nil {
		return errs.FileError(err, root)
	}
	if !f.Mode().IsDir() {
		return errors.New("positional argument <dir> must be a directory")
	}

	address := ctx.String("address")
	cert := ctx.String("cert")
	key := ctx.String("key")
	roots := ctx.String("roots")

	switch {
	case address == "":
		return errs.RequiredFlag(ctx, "address")
	case roots != "" && cert == "":
		return errs.RequiredWithFlag(ctx, "roots", "cert")
	case roots != "" && key == "":
		return errs.RequiredWithFlag(ctx, "roots", "key")
	case cert != "" && key == "":
		return errs.RequiredWithFlag(ctx, "cert", "key")
	case key != "" && cert == "":
		return errs.RequiredWithFlag(ctx, "key", "cert")
	}

	var tlsConfig *tls.Config
	if roots != "" {
		b, err := utils.ReadFile(roots)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)
		tlsConfig = &tls.Config{
			ClientCAs:  pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
	}

	l, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on at %s", address)
	}

	srv := &http.Server{
		Handler:   http.FileServer(http.Dir(root)),
		TLSConfig: tlsConfig,
	}
	if cert != "" && key != "" {
		fmt.Printf("Serving HTTPS at %s ...\n", l.Addr().String())
		err = srv.ServeTLS(l, cert, key)
	} else {
		fmt.Printf("Serving HTTP at %s...\n", l.Addr().String())
		err = srv.Serve(l)
	}
	if err != nil && err != http.ErrServerClosed {
		return errors.Wrap(err, "file server failed")
	}

	return nil
}
