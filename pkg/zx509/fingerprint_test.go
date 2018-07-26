// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"testing"
)

var randomData = []byte("somerandomdata")

type fpJSONTestStruct struct {
	FP CertificateFingerprint `json:"fp"`
}

func TestMD5Fingerprint(t *testing.T) {
	fingerprint := MD5Fingerprint(randomData)

	if fingerprint.Hex() != "5698ed1e3d65a854fc702393fb2049b4" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"5698ed1e3d65a854fc702393fb2049b4"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA1Fingerprint(t *testing.T) {
	fingerprint := SHA1Fingerprint(randomData)

	if fingerprint.Hex() != "26f30f9a9ff52d1cfbd18c4ca4d54a898b05ce0d" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"26f30f9a9ff52d1cfbd18c4ca4d54a898b05ce0d"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA256Fingerprint(t *testing.T) {
	fingerprint := SHA256Fingerprint(randomData)

	if fingerprint.Hex() != "dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}

func TestSHA512Fingerprint(t *testing.T) {
	fingerprint := SHA512Fingerprint(randomData)

	if fingerprint.Hex() != "4e8a382161e2ee2fe460cbf99a2df371a7ce3b2587a637a6c3cec91fa2920ab969b40e4c9ec12ef12405e175d0b09baf35a46c4349e658def41b6d296bad3fd2" {
		t.Fatal("invalid fingerprint:", fingerprint.Hex())
	}
	s := fpJSONTestStruct{
		FP: fingerprint,
	}
	b, _ := json.Marshal(&s)
	if `{"fp":"4e8a382161e2ee2fe460cbf99a2df371a7ce3b2587a637a6c3cec91fa2920ab969b40e4c9ec12ef12405e175d0b09baf35a46c4349e658def41b6d296bad3fd2"}` != string(b) {
		t.Fatalf("invalid json: %s", b)
	}
}
