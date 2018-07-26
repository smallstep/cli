// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/pem"
	"io/ioutil"
	"testing"
)

const testdataPrefix = "testdata/"

func TestDetectSelfSigned(t *testing.T) {
	tests := []struct {
		Filename string
		Expected bool
	}{
		{
			Filename: "self-signed.pem",
			Expected: true,
		},
		{
			Filename: "self-signed-invalid-sig.pem",
			Expected: false,
		},
		{
			Filename: "self-signed-invalid-name.pem",
			Expected: false,
		},
		{
			Filename: "dadrian.io.pem",
			Expected: false,
		},
		{
			Filename: "self-signed-md5-rsa.pem",
			Expected: true,
		},
	}
	for _, test := range tests {
		path := testdataPrefix + test.Filename
		b, err := ioutil.ReadFile(path)
		if err != nil {
			t.Fatalf("could not open %s: %s", test.Filename, err)
		}
		p, _ := pem.Decode(b)
		if p == nil {
			t.Fatalf("bad pem %s", test.Filename)
		}
		c, err := ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatalf("could not parse %s: %s", test.Filename, err)
		}
		if c.SelfSigned != test.Expected {
			t.Errorf("expected %s to have SelfSigned = %t", test.Filename, test.Expected)
			t.Fail()
		}
	}
}

func TestParseEmailInDN(t *testing.T) {
	const expectedEmail = "ca-winshuttle@dfn.de"
	b, err := ioutil.ReadFile(testdataPrefix + "email-in-subject.pem")
	if err != nil {
		t.Fatalf("could not open file: %s", err)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		t.Fatalf("bad pem")
	}
	c, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("could not parse: %s", err)
	}
	if len(c.Subject.EmailAddress) != 1 {
		t.Error("did not parse email address")
	}
	if email := c.Subject.EmailAddress[0]; email != expectedEmail {
		t.Errorf("mismatched email address, expected %s, got %s", expectedEmail, email)
	}
}
