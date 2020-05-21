package pkiutils

import (
	"crypto/x509/pkix"
	"strings"
)

// ParseSubject takes a subject and converts it into a pkix.Name object.
//
// If the subject follows the standard form of a distinguished name such
// as CN=myhost,O=my company,C=US then it is parsed into individual fields
// in a pkix.Name object.
//
// If it does not match the pattern then the subject is just returned as
// the CommonName of the pkix.Name object.
//
// The following DN fields are supported:
//    CN: CommonName
//    OU: OrganizationalUnit
//     O: Organization
//     L: Locality
//    ST: Province (also S, P or SP are allowed)
//     C: Country
//
// If an unknown field is encountered, the entire subject is treated as
// the CN.
func ParseSubject(s string) (pkix.Name, bool) {
	subject := pkix.Name{}

	// assume it's a DN to start (avoiding very complex regex issues)
	fields := strings.Split(s, ",")
	isDN := true
	for _, field := range fields {
		pair := strings.SplitN(strings.TrimSpace(field), "=", 2)
		switch pair[0] {
		case "C":
			subject.Country = []string{pair[1]}
		case "ST", "S", "SP", "P":
			subject.Province = []string{pair[1]}
		case "L":
			subject.Locality = []string{pair[1]}
		case "O":
			subject.Organization = []string{pair[1]}
		case "OU":
			subject.OrganizationalUnit = []string{pair[1]}
		case "CN":
			subject.CommonName = pair[1]
		default:
			isDN = false // this is not a DN
		}
	}

	if !isDN {
		subject.Country = []string{}
		subject.Province = []string{}
		subject.Locality = []string{}
		subject.Organization = []string{}
		subject.OrganizationalUnit = []string{}
		subject.CommonName = s
	}
	return subject, isDN
}
