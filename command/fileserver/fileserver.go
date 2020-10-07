package fileserver

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/pkg/errors"

	"github.com/smallstep/cli/errs"

	"github.com/smallstep/cli/command"
	"github.com/urfave/cli"
)

func init() {
	cmd := cli.Command{
		Name:   "fileserver",
		Hidden: true,
		Action: command.ActionFunc(fileServerAction),
		Usage:  "start an HTTP(S) server serving the contents of a path",
		UsageText: `step fileserver <dir>
[--address=<address>] [--cert=<path>] [--key=<path>]`,
		Description: `**step fileserver** command starts an HTTP(S) server serving the contents of a file
system.

This command is experimental and only intended for test purposes.

## POSITIONAL ARGUMENTS

<dir>
: The directory used as root for the HTTP file server.

## EXAMPLES

Start an HTTP file server on port 8080.
'''
$ step fileserver --address :8080 /path/to/root
'''

Start an HTTPS file server on 127.0.0.1:8443.
'''
$ step ca certificate 127.0.0.1 localhost.crt localhost.key
...
$ step fileserver --address 127.0.0.1:8443 \
  --cert localhost.crt --key localhost.key /path/to/root
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "address",
				Usage: "The TCP <address> to listen on (e.g. \":8443\").",
				Value: ":0",
			},
			cli.StringFlag{
				Name:  "cert",
				Usage: `The <path> to the TLS certificate to use.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: `The <path> to the key corresponding to the certificate.`,
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

	switch {
	case address == "":
		return errs.RequiredFlag(ctx, "address")
	case cert != "" && key == "":
		return errs.RequiredWithFlag(ctx, "cert", "key")
	case key != "" && cert == "":
		return errs.RequiredWithFlag(ctx, "key", "cert")
	}

	l, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on at %s", address)
	}

	handler := http.FileServer(http.Dir(root))
	if cert != "" && key != "" {
		fmt.Printf("Serving HTTPS at %s ...\n", l.Addr().String())
		err = http.ServeTLS(l, handler, cert, key)
	} else {
		fmt.Printf("Serving HTTP at %s...\n", l.Addr().String())
		err = http.Serve(l, handler)
	}
	if err != nil && err != http.ErrServerClosed {
		return errors.Wrap(err, "file server failed")
	}

	return nil
}
