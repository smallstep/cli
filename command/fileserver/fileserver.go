package fileserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/utils"
)

func init() {
	cmd := cli.Command{
		Name:   "fileserver",
		Hidden: true,
		Action: command.ActionFunc(fileServerAction),
		Usage:  "start an HTTP(S) server serving the contents of a path",
		UsageText: `step fileserver <dir>
[**--address**=<address>] [**--cert**=<file>] [**--key**=<file>] [**--roots**=<file>]
[**--pidfile**=<file>]`,
		Description: `**step fileserver** command starts an HTTP(S) server that serves
the contents of a file system. If the server is running using certificates, sending the
HUP signal will reload the certificates.

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
			cli.StringFlag{
				Name:  "pidfile",
				Usage: `The path to the <file> to write the process ID.`,
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

	var r *tlsRenewer
	var tlsConfig *tls.Config
	if cert != "" {
		r, err = newTLSRenewer(cert, key, roots)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			GetConfigForClient: r.GetConfigForClient,
		}
	}

	if pidfile := ctx.String("pidfile"); pidfile != "" {
		pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
		//nolint:gosec // 0644 (-rw-r--r--) are common permissions for a pid file
		if err := os.WriteFile(pidfile, pid, 0644); err != nil {
			return fmt.Errorf("error writing pidfile: %w", err)
		}
		defer os.Remove(pidfile)
	}

	l, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("error listening at %s: %w", address, err)
	}

	srv := &http.Server{
		Handler:           http.FileServer(http.Dir(root)),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 15 * time.Second,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		signalHandler(r, srv)
		wg.Done()
	}()

	go func() {
		if cert != "" {
			log.Printf("serving HTTPS at %s\n", l.Addr().String())
			err = srv.ServeTLS(l, cert, key)
		} else {
			log.Printf("serving HTTP at %s\n", l.Addr().String())
			err = srv.Serve(l)
		}
		wg.Done()
	}()

	wg.Wait()

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("file server failed: %w", err)
	}

	return nil
}

func signalHandler(r *tlsRenewer, srv *http.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	for sig := range signals {
		switch sig {
		case syscall.SIGHUP:
			if err := r.Reload(); err != nil {
				log.Printf("error reloading server: %v", err)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Println("shutting down")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("error shutting down the server: %v", err)
			}
			cancel()
			return
		}
	}
}

// tlsRenewer implements the tls.Config callback GetConfigForClient that returns
// the TLS configuration. It will reload the configured files if Reload is
// called.
type tlsRenewer struct {
	certFile  string
	keyFile   string
	rootFile  string
	tlsConfig *tls.Config
	rw        sync.RWMutex
}

func newTLSRenewer(certFile, keyFile, rootFile string) (*tlsRenewer, error) {
	renewer := &tlsRenewer{
		certFile: certFile,
		keyFile:  keyFile,
		rootFile: rootFile,
	}
	if err := renewer.Reload(); err != nil {
		return nil, err
	}
	return renewer, nil
}

func (r *tlsRenewer) Reload() error {
	if r == nil {
		return nil
	}

	log.Printf("reloading TLS configuration")
	var clientCAs *x509.CertPool
	var clientAuth tls.ClientAuthType
	if r.rootFile != "" {
		b, err := utils.ReadFile(r.rootFile)
		if err != nil {
			return err
		}
		clientCAs = x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(b)
		clientAuth = tls.RequireAndVerifyClientCert
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}

	r.rw.Lock()
	r.tlsConfig = &tls.Config{
		ClientCAs:  clientCAs,
		ClientAuth: clientAuth,
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}
	r.rw.Unlock()
	return nil
}

func (r *tlsRenewer) GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	r.rw.RLock()
	defer r.rw.RUnlock()
	return r.tlsConfig, nil
}
