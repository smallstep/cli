// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import "testing"

func TestNameString(t *testing.T) {
	tests := []struct {
		name     Name
		expected string
	}{
		{
			name:     Name{},
			expected: "",
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
			expected: `CN=common, OU=0x21, O=University of Michigan, street=2260 Hayward St, L=Ann Arbor, ST=Michigan, postalCode=48109, C=US, C=RU, serialNumber=12345, CN=name, serialNumber=67890`,
		},
		{
			name: Name{
				SerialNumber: "12345",
				CommonName:   "common",
				PostalCode:   []string{"48109"},
				OriginalRDNS: RDNSequence{
					[]AttributeTypeAndValue{
						{Type: oidPostalCode, Value: "48109"},
						{Type: oidSerialNumber, Value: "12345"},
						{Type: oidCommonName, Value: "common"},
					},
				},
			},
			expected: `postalCode=48109, serialNumber=12345, CN=common`,
		},
	}
	for i, test := range tests {
		s := test.name.String()
		if s != test.expected {
			t.Errorf("%d: expected %s, got %s", i, test.expected, s)
		}
	}
}
