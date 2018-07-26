// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"testing"
)

func TestIssuerAlternativeNameJSON(t *testing.T) {
	// TODO: See pkix/json_test.go for an example.
}

func TestSubjectAlternativeNameJSON(t *testing.T) {
	// TODO: See pkix/json_test.go for an example.
}

func TestNameConstraintJSON(t *testing.T) {
	// TODO: See pkix/json_test.go for an example.
}

func TestValidationLevelJSON(t *testing.T) {
	tests := []struct {
		in  CertValidationLevel
		out string
	}{
		{
			in:  UnknownValidationLevel,
			out: `"unknown"`,
		},
		{
			in:  DV,
			out: `"DV"`,
		},
		{
			in:  OV,
			out: `"OV"`,
		},
		{
			in:  EV,
			out: `"EV"`,
		},
		{
			in:  1234,
			out: `"unknown"`,
		},
		{
			in:  -1,
			out: `"unknown"`,
		},
	}
	for _, test := range tests {
		b, err := json.Marshal(&test.in)
		if err != nil {
			t.Errorf("%s", err)
			continue
		}
		if s := string(b); test.out != s {
			t.Errorf("got %s, wanted %s", s, test.out)
			continue
		}
	}
}
