// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func BenchmarkParse(b *testing.B) {
	fileBytes, _ := ioutil.ReadFile("testdata/davidadrian.org.cert")
	p, _ := pem.Decode(fileBytes)
	for i := 0; i < b.N; i++ {
		ParseCertificate(p.Bytes)
	}
}

func BenchmarkEncode(b *testing.B) {
	fileBytes, _ := ioutil.ReadFile("testdata/davidadrian.org.cert")
	p, _ := pem.Decode(fileBytes)
	c, _ := ParseCertificate(p.Bytes)
	for i := 0; i < b.N; i++ {
		json.Marshal(c)
	}
}
