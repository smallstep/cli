package plugin

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"
	"go.step.sm/crypto/pemutil"
)

// LookPath searches for an executable named step-<name>-plugin in the $(step
// path)/plugins directory or in the directories named by the PATH environment
// variable.
func LookPath(name string) (string, error) {
	fileName := "step-" + name + "-plugin"
	path := filepath.Join(step.BasePath(), "plugins", fileName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return exec.LookPath(fileName)
}

// Run starts the given command with the arguments in the context and waits for
// it to complete.
func Run(ctx *cli.Context, file string) error {
	args := ctx.Args()
	cmd := exec.Command(file, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type signer struct {
	crypto.PublicKey
	name     string
	kms, key string
}

// Creates a signer using `step-kms-plugin` as the signer.
func Signer(kms, key string) (crypto.Signer, error) {
	name, err := LookPath("kms")
	if err != nil {
		return nil, err
	}

	args := []string{"key"}
	if kms != "" {
		args = append(args, "--kms", kms)
	}
	args = append(args, key)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	pub, err := pemutil.Parse(out)
	if err != nil {
		return nil, err
	}

	return &signer{
		PublicKey: pub,
		name:      name,
		kms:       kms,
		key:       key,
	}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	args := []string{"sign", "--format", "base64"}
	if s.kms != "" {
		args = append(args, "--kms", s.kms)
	}
	if _, ok := s.PublicKey.(*rsa.PublicKey); ok {
		if _, pss := opts.(*rsa.PSSOptions); pss {
			args = append(args, "--pss")
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			args = append(args, "--alg", "SHA256")
		case crypto.SHA384:
			args = append(args, "--alg", "SHA384")
		case crypto.SHA512:
			args = append(args, "--alg", "SHA512")
		default:
			return nil, errors.Errorf("unsupported hash function %q", opts.HashFunc().String())
		}
	}
	args = append(args, s.key)

	cmd := exec.Command(s.name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(digest)
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(out))
}
