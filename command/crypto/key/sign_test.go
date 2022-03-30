package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestReadKey_PrivateKey(t *testing.T) {
	arbitraryPrivateKey := "0x157c3200d896c0595a205109c5b5656e82621e8214a12a9561727870f5867962"
	f, err := prepareFile(arbitraryPrivateKey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()
	flags := &flag.FlagSet{}
	flags.String("alg", "secp256k1", "")
	ctx := cli.NewContext(nil, flags, nil)

	pk, err := readKey(f.Name(), false, ctx)
	if err != nil {
		t.Errorf("%v", err)
	}

	assert.IsType(t, &ecdsa.PrivateKey{}, pk)
}

func TestReadKey_PublicKey(t *testing.T) {
	arbitraryPubKey := "02d1e996bf09686ca22e5303e7d3abda4ccbbcdee94f5eb3adf6cad7238f27f840"
	f, err := prepareFile(arbitraryPubKey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()
	flags := &flag.FlagSet{}
	flags.String("alg", "secp256k1", "")
	ctx := cli.NewContext(nil, flags, nil)

	pk, err := readKey(f.Name(), true, ctx)
	if err != nil {
		t.Errorf("%v", err)
	}

	assert.IsType(t, &ecdsa.PublicKey{}, pk)
}

func TestSign(t *testing.T) {
	var capturedOutput bytes.Buffer
	output = &capturedOutput
	defer func() {
		output = os.Stdout
	}()
	arbitraryKeyPair := struct {
		priv string
		pub  string
	}{
		priv: "0xb2cf8112327c38acc3b16b2cea56c684aa94580caae76e29dcb244f19bec88e2",
		pub:  "0224e7f25110dabeb26e1f94760dc9abe15fd35d5cd2f60ce99d5fe3f35b552fcc",
	}
	arbitraryData := "test data"
	pkFile, err := prepareFile(arbitraryKeyPair.priv)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		_ = os.Remove(pkFile.Name())
	}()
	dataFile, err := prepareFile(arbitraryData)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		_ = os.Remove(dataFile.Name())
	}()
	flags := &flag.FlagSet{}
	flags.String("alg", "secp256k1", "")
	flags.String("key", pkFile.Name(), "")
	flags.String("format", "hex", "")
	_ = flags.Parse([]string{dataFile.Name()})
	ctx := cli.NewContext(nil, flags, nil)

	assert.NoError(t, signAction(ctx))

	actual := strings.TrimSpace(capturedOutput.String())
	sig, err := hex.DecodeString(actual)
	if err != nil {
		t.Fatalf("%v", err)
	}
	// now verify it
	pubKey, err := hex.DecodeString(arbitraryKeyPair.pub)
	if err != nil {
		t.Fatalf("%v", err)
	}
	secpPubKey, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.True(t, ecdsa.VerifyASN1(secpPubKey.ToECDSA(), hash(crypto.SHA256, []byte(arbitraryData)), sig))
}

// remember to delete file after use
func prepareFile(s string) (*os.File, error) {
	f, err := os.CreateTemp("", "test-")
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(s); err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return f, nil
}
