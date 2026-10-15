package provisioner

import (
	"testing"

	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_updateACMEDetails(t *testing.T) {
	const (
		oldPrefix = "https://ca.example.com/acme/acme/account-hash/"
		newPrefix = "https://ca.example.org/acme/acme/account-hash/"
	)
	tests := []struct {
		name string
		args []string
		want *linkedca.ACMEProvisioner
	}{
		{"ok/unchanged", nil, &linkedca.ACMEProvisioner{
			Challenges:        []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_DNS_PERSIST_01},
			IssuerDomainNames: []string{"ca.example.com", "ca.example.net"},
			AccountHashPrefix: oldPrefix,
		}},
		{"ok/add", []string{
			"--challenge", "dns-01",
			"--issuer-domain-name", "ca.example.org",
			"--issuer-domain-name", "ca.example.com",
			"--account-hash-prefix", newPrefix,
		}, &linkedca.ACMEProvisioner{
			Challenges: []linkedca.ACMEProvisioner_ChallengeType{
				linkedca.ACMEProvisioner_DNS_PERSIST_01, linkedca.ACMEProvisioner_DNS_01,
			},
			IssuerDomainNames: []string{"ca.example.com", "ca.example.net", "ca.example.org"},
			AccountHashPrefix: newPrefix,
		}},
		{"ok/remove", []string{
			"--remove-challenge", "dns-persist-01",
			"--remove-issuer-domain-name", "ca.example.com",
			"--account-hash-prefix", "",
		}, &linkedca.ACMEProvisioner{
			Challenges:        []linkedca.ACMEProvisioner_ChallengeType{},
			IssuerDomainNames: []string{"ca.example.net"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &linkedca.Provisioner{
				Type: linkedca.Provisioner_ACME,
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_ACME{
						ACME: &linkedca.ACMEProvisioner{
							Challenges:        []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_DNS_PERSIST_01},
							IssuerDomainNames: []string{"ca.example.com", "ca.example.net"},
							AccountHashPrefix: oldPrefix,
						},
					},
				},
			}
			require.NoError(t, updateACMEDetails(newACMEContext(t, tt.args...), p))
			assert.Equal(t, tt.want, p.GetDetails().GetACME())
		})
	}
}
