package provisioner

import (
	"flag"
	"testing"

	"github.com/smallstep/linkedca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// newACMEContext returns a context with the ACME provisioner flags parsed from
// args.
func newACMEContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	for _, f := range []cli.Flag{
		forceCNFlag, requireEABFlag, challengeFlag, removeChallengeFlag,
		attestationFormatFlag, removeAttestationFormatFlag, attestationRootsFlag,
		issuerDomainNameFlag, removeIssuerDomainNameFlag, accountHashPrefixFlag,
	} {
		f.Apply(set)
	}
	require.NoError(t, set.Parse(args))
	return cli.NewContext(&cli.App{}, set, nil)
}

func Test_validateChallengeFlag(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"ok/dns-persist-01", []string{"--challenge", "dns-persist-01"}, false},
		{"ok/dns-persist-01 uppercase", []string{"--challenge", "DNS-PERSIST-01"}, false},
		{"ok/remove dns-persist-01", []string{"--remove-challenge", "dns-persist-01"}, false},
		{"fail/challenge", []string{"--challenge", "dns-persist-02"}, true},
		{"fail/remove-challenge", []string{"--remove-challenge", "dns-persist-02"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChallengeFlag(newACMEContext(t, tt.args...), linkedca.Provisioner_ACME)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_acmeChallengeToLinkedca(t *testing.T) {
	got := acmeChallengeToLinkedca([]string{"http-01", "dns-01", "DNS-PERSIST-01", "tls-alpn-01", "device-attest-01"})
	assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{
		linkedca.ACMEProvisioner_HTTP_01,
		linkedca.ACMEProvisioner_DNS_01,
		linkedca.ACMEProvisioner_DNS_PERSIST_01,
		linkedca.ACMEProvisioner_TLS_ALPN_01,
		linkedca.ACMEProvisioner_DEVICE_ATTEST_01,
	}, got)
}

func Test_createACMEDetails(t *testing.T) {
	ctx := newACMEContext(t,
		"--challenge", "dns-01", "--challenge", "dns-persist-01",
		"--issuer-domain-name", "ca.example.com",
		"--issuer-domain-name", "ca.example.net",
		"--issuer-domain-name", "ca.example.com",
		"--account-hash-prefix", "https://ca.example.com/acme/acme/account-hash/",
	)
	got, err := createACMEDetails(ctx)
	require.NoError(t, err)
	assert.Equal(t, &linkedca.ACMEProvisioner{
		Challenges: []linkedca.ACMEProvisioner_ChallengeType{
			linkedca.ACMEProvisioner_DNS_01, linkedca.ACMEProvisioner_DNS_PERSIST_01,
		},
		IssuerDomainNames: []string{"ca.example.com", "ca.example.net"},
		AccountHashPrefix: "https://ca.example.com/acme/acme/account-hash/",
	}, got.GetACME())
}
