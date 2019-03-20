package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

func TestToStepX509(t *testing.T) {
	b, err := ioutil.ReadFile("test_files/ca.crt")
	assert.FatalError(t, err)
	block, rest := pem.Decode(b)
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding test_files/ca.crt")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	scert, err := stepx509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *stepx509.Certificate
	}{
		{"ok", args{cert}, scert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToStepX509(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToStepX509() = %v, want %v", got, tt.want)
			}
		})
	}
}
