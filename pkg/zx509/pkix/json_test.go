// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"testing"
)

func TestAttributeTypeValueJSON(t *testing.T) {
	tests := []struct {
		atv      AttributeTypeAndValue
		expected string
	}{
		{
			atv:      AttributeTypeAndValue{Type: oidCommonName, Value: "some.common.name"},
			expected: `{"type":"2.5.4.3","value":"some.common.name"}`,
		},
		{
			atv:      AttributeTypeAndValue{},
			expected: `{}`,
		},
		{
			atv:      AttributeTypeAndValue{Type: []int{}, Value: "some value"},
			expected: `{"value":"some value"}`,
		},
	}
	for i, test := range tests {
		b, err := json.Marshal(&test.atv)
		if len(test.expected) > 0 && err != nil {
			t.Errorf("%d: failed marshal: %s", i, err)
			continue
		}
		if s := string(b); s != test.expected {
			t.Errorf("%d: expected %s, got %s", i, test.expected, s)
		}
		parsed := AttributeTypeAndValue{}
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Errorf("%d: could not unmarshal: %s", i, err)
		}
		if !test.atv.Type.Equal(parsed.Type) {
			t.Errorf("%d: expected %v, got %v", i, test.atv.Type, parsed.Type)
		}
		if test.atv.Value != nil {
			parsedValue, _ := parsed.Value.(string)
			if test.atv.Value.(string) != parsedValue {
				t.Errorf("%d: expected %v, got %v", i, test.atv.Value, parsed.Value)
			}
		}
	}
}

func TestExtensionJSON(t *testing.T) {
	tests := []struct {
		ext      Extension
		expected string
	}{
		{
			ext: Extension{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
				Critical: false,
				Value:    []byte{6, 7, 8, 9, 0},
			},
			expected: `{"id":"1.2.3.4.5","critical":false,"value":"BgcICQA="}`,
		},
	}
	for i, test := range tests {
		b, err := json.Marshal(&test.ext)
		if err != nil {
			t.Errorf("%d: failed to marshal: %s", i, err)
			continue
		}
		if s := string(b); s != test.expected {
			t.Errorf("%d: expected %s, got %s", i, test.expected, s)
		}
		parsed := Extension{}
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Errorf("%d: could not unmarshal: %s", i, err)
		}
		if !test.ext.Id.Equal(parsed.Id) {
			t.Errorf("%d: unmarshaled Id mismatch, expected %v, got %v", i, test.ext.Id, parsed.Id)
		}
	}
}

func TestNameJSON(t *testing.T) {
	tests := []struct {
		name     Name
		expected string
	}{
		{
			name:     Name{},
			expected: `{}`,
		},
		{
			name: Name{
				SerialNumber:       "12345",
				CommonName:         "common",
				Country:            []string{"US", "RU"},
				Organization:       []string{"University of Michigan"},
				OrganizationalUnit: []string{"0x21"},
				Locality:           []string{"Ann Arbor"},
				Province:           []string{"Michigan"},
				StreetAddress:      []string{"2260 Hayward St"},
				PostalCode:         []string{"48109"},
				DomainComponent:    nil,
				ExtraNames:         []AttributeTypeAndValue{{Type: oidCommonName, Value: "name"}, {Type: oidSerialNumber, Value: "67890"}},
			},
			expected: `{"common_name":["common","name"],"serial_number":["12345","67890"],"country":["US","RU"],"locality":["Ann Arbor"],"province":["Michigan"],"street_address":["2260 Hayward St"],"organization":["University of Michigan"],"organizational_unit":["0x21"],"postal_code":["48109"]}`,
		},
	}
	for i, test := range tests {
		b, err := json.Marshal(&test.name)
		if len(test.expected) > 0 && err != nil {
			t.Errorf("%d: failed marshal: %s", i, err)
			continue
		}
		if s := string(b); s != test.expected {
			t.Errorf("%d: expected %s, got %s", i, test.expected, s)
		}
		parsed := Name{}
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Errorf("%d: could not unmarshal: %s", i, err)
		}
		// TODO: Check equality of parsed and original.
	}
}

func TestOtherNameJSON(t *testing.T) {
	tests := []struct {
		otherName OtherName
		expected  string
		unmarshal bool
	}{
		{
			otherName: OtherName{},
			expected:  `{}`,
			unmarshal: false,
		},
		{
			otherName: OtherName{
				TypeID: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 2, 2}, // image/JPEG 2.16.840.1.113730.2.2
				Value: asn1.RawValue{
					Tag:        0,
					Class:      asn1.ClassContextSpecific,
					IsCompound: true,
					Bytes:      []byte{0, 1, 2, 3, 4, 5},
				},
			},
			expected:  `{"id":"2.16.840.1.113730.2.2","value":"AAECAwQF"}`,
			unmarshal: true,
		},
	}
	for i, test := range tests {
		b, err := json.Marshal(&test.otherName)
		if len(test.expected) > 0 && err != nil {
			t.Errorf("%d: unabled to marshal: %s", i, err)
			continue
		}
		if s := string(b); s != test.expected {
			t.Errorf("%d: expected %s, got %s", i, test.expected, s)
		}
		parsed := OtherName{}
		if test.unmarshal {
			if err := json.Unmarshal(b, &parsed); err != nil {
				t.Errorf("%d: could not unmarshal: %s", i, err)
			}
			// TODO: Check equality of parsed and original
		}
	}
}
