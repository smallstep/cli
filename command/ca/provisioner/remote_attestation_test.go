package provisioner

import (
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/linkedca"
)

// remoteAttestationCommandContext returns the context of the given command run
// with the given arguments.
func remoteAttestationCommandContext(t *testing.T, cmd cli.Command, args ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	for _, f := range cmd.Flags {
		f.Apply(set)
	}
	require.NoError(t, set.Parse(args))
	return cli.NewContext(cli.NewApp(), set, nil)
}

// remoteAttestationTestFiles writes a root certificate, a bundle of a root and
// an intermediate, and a PEM file with a key and no certificate, and returns
// their paths and the PEM of the certificate files.
func remoteAttestationTestFiles(t *testing.T) (rootFile, bundleFile, keyFile string, rootPEM, bundlePEM []byte) {
	t.Helper()
	ca, err := minica.New()
	require.NoError(t, err)
	key, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	keyBlock, err := pemutil.Serialize(key)
	require.NoError(t, err)

	dir := t.TempDir()
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
	bundlePEM = slices.Concat(rootPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Intermediate.Raw}))
	rootFile = filepath.Join(dir, "root.crt")
	bundleFile = filepath.Join(dir, "bundle.crt")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(rootFile, rootPEM, 0o600))
	require.NoError(t, os.WriteFile(bundleFile, bundlePEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(keyBlock), 0o600))
	return rootFile, bundleFile, keyFile, rootPEM, bundlePEM
}

func TestCreateACMEDetailsRemoteAttestation(t *testing.T) {
	rootFile, bundleFile, keyFile, rootPEM, bundlePEM := remoteAttestationTestFiles(t)
	remoteAttest01 := []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_REMOTE_ATTEST_01}
	tests := []struct {
		name    string
		args    []string
		want    *linkedca.ACMEProvisioner
		wantErr string
	}{
		{"ok challenge only", []string{"--challenge", "remote-attest-01"},
			&linkedca.ACMEProvisioner{Challenges: remoteAttest01}, ""},
		{"ok require", []string{"--challenge", "remote-attest-01", "--remote-attestation-require"}, &linkedca.ACMEProvisioner{
			Challenges:        remoteAttest01,
			RemoteAttestation: &linkedca.ACMERemoteAttestation{Require: true},
		}, ""},
		{"ok require false", []string{"--challenge", "remote-attest-01", "--remote-attestation-require=false"},
			&linkedca.ACMEProvisioner{Challenges: remoteAttest01}, ""},
		{"ok all", []string{
			"--challenge", "remote-attest-01",
			"--require-eab",
			"--remote-attestation-require",
			"--remote-attestation-format", "TDX",
			"--remote-attestation-format", "sev-snp",
			"--remote-attestation-format", "confidential-space",
			"--remote-attestation-format", "tdx",
			"--remote-attestation-claims-hint", "ueid",
			"--remote-attestation-claims-hint", "measurements",
			"--remote-attestation-tdx-roots", rootFile,
			"--remote-attestation-sev-snp-roots", bundleFile,
			"--remote-attestation-cs-roots", rootFile,
			"--remote-attestation-cs-audience", "https://ca.example.com/acme/rats/directory",
			"--remote-attestation-cs-max-token-age", "2m",
			"--remote-attestation-cs-image-digest", "sha256:aaaa",
			"--remote-attestation-cs-image-signer-key-id", "key-1",
			"--remote-attestation-cs-require-support-attribute", "STABLE",
			"--remote-attestation-cs-hwmodel", "GCP_INTEL_TDX",
			"--remote-attestation-cs-hwmodel", "GCP_AMD_SEV",
			"--remote-attestation-cs-swname", "CONFIDENTIAL_SPACE",
			"--remote-attestation-cs-project", "workloads",
			"--remote-attestation-cs-service-account", "workload@workloads.iam.gserviceaccount.com",
		}, &linkedca.ACMEProvisioner{
			RequireEab: true,
			Challenges: remoteAttest01,
			RemoteAttestation: &linkedca.ACMERemoteAttestation{
				Require:     true,
				Formats:     []string{"tdx", "sev-snp", "confidential-space"},
				ClaimsHint:  []string{"ueid", "measurements"},
				TdxRoots:    rootPEM,
				SevSnpRoots: bundlePEM,
				ConfidentialSpace: &linkedca.ACMEConfidentialSpace{
					Roots:                    rootPEM,
					Audience:                 "https://ca.example.com/acme/rats/directory",
					MaxTokenAge:              "2m",
					ImageDigests:             []string{"sha256:aaaa"},
					ImageSignerKeyIds:        []string{"key-1"},
					RequireSupportAttributes: []string{"STABLE"},
					Hwmodels:                 []string{"GCP_INTEL_TDX", "GCP_AMD_SEV"},
					Swnames:                  []string{"CONFIDENTIAL_SPACE"},
					ProjectIds:               []string{"workloads"},
					ServiceAccounts:          []string{"workload@workloads.iam.gserviceaccount.com"},
				},
			},
		}, ""},
		{"ok confidential space only", []string{"--challenge", "remote-attest-01", "--remote-attestation-cs-roots", rootFile}, &linkedca.ACMEProvisioner{
			Challenges: remoteAttest01,
			RemoteAttestation: &linkedca.ACMERemoteAttestation{
				ConfidentialSpace: &linkedca.ACMEConfidentialSpace{Roots: rootPEM},
			},
		}, ""},
		{"ok confidential space without the challenge", []string{"--remote-attestation-cs-project", "workloads"}, &linkedca.ACMEProvisioner{
			RemoteAttestation: &linkedca.ACMERemoteAttestation{
				ConfidentialSpace: &linkedca.ACMEConfidentialSpace{ProjectIds: []string{"workloads"}},
			},
		}, ""},
		{"ok confidential-space format with the embedded root", []string{
			"--challenge", "remote-attest-01", "--remote-attestation-format", "confidential-space",
		}, &linkedca.ACMEProvisioner{
			Challenges:        remoteAttest01,
			RemoteAttestation: &linkedca.ACMERemoteAttestation{Formats: []string{"confidential-space"}},
		}, ""},
		{"ok default confidential-space format with the embedded root", []string{
			"--challenge", "remote-attest-01", "--remote-attestation-cs-project", "workloads",
		}, &linkedca.ACMEProvisioner{
			Challenges: remoteAttest01,
			RemoteAttestation: &linkedca.ACMERemoteAttestation{
				ConfidentialSpace: &linkedca.ACMEConfidentialSpace{ProjectIds: []string{"workloads"}},
			},
		}, ""},
		{"fail format", []string{"--remote-attestation-format", "sgx"}, nil,
			"invalid value 'sgx' for flag '--remote-attestation-format'; options are tdx, sev-snp, confidential-space"},
		{"fail empty claims hint", []string{"--remote-attestation-claims-hint", ""}, nil,
			"missing value for flag '--remote-attestation-claims-hint'"},
		{"fail empty project", []string{"--remote-attestation-cs-project", ""}, nil,
			"missing value for flag '--remote-attestation-cs-project'"},
		{"fail zero max token age", []string{"--remote-attestation-cs-max-token-age", "0s"}, nil,
			"invalid value '0s' for flag '--remote-attestation-cs-max-token-age'; it must be a duration greater than 0"},
		{"fail bad max token age", []string{"--remote-attestation-cs-max-token-age", "five minutes"}, nil,
			"invalid value 'five minutes' for flag '--remote-attestation-cs-max-token-age'; it must be a duration greater than 0"},
		{"fail tdx roots without a certificate", []string{"--remote-attestation-tdx-roots", keyFile}, nil,
			"error loading certificates from " + keyFile},
		{"fail sev-snp roots missing", []string{"--remote-attestation-sev-snp-roots", filepath.Join(t.TempDir(), "missing.crt")}, nil,
			"error loading certificates from"},
		{"fail cs roots without a certificate", []string{"--remote-attestation-cs-roots", keyFile}, nil,
			"error loading certificates from " + keyFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createACMEDetails(remoteAttestationCommandContext(t, addCommand(), tt.args...))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Truef(t, proto.Equal(tt.want, got.GetACME()), "got %v", got.GetACME())
		})
	}
}

func TestUpdateACMEDetailsRemoteAttestation(t *testing.T) {
	rootFile, bundleFile, keyFile, rootPEM, bundlePEM := remoteAttestationTestFiles(t)
	current := &linkedca.ACMEProvisioner{
		RequireEab: true,
		Challenges: []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_REMOTE_ATTEST_01},
		RemoteAttestation: &linkedca.ACMERemoteAttestation{
			Require:     true,
			Formats:     []string{"tdx", "confidential-space"},
			ClaimsHint:  []string{"ueid"},
			TdxRoots:    []byte("tdx roots"),
			SevSnpRoots: []byte("sev-snp roots"),
			ConfidentialSpace: &linkedca.ACMEConfidentialSpace{
				Roots:                    []byte("cs roots"),
				Audience:                 "https://ca.example.com/acme/rats/directory",
				MaxTokenAge:              "10m",
				ImageDigests:             []string{"sha256:aaaa"},
				ImageSignerKeyIds:        []string{"key-1"},
				RequireSupportAttributes: []string{"STABLE"},
				Hwmodels:                 []string{"GCP_INTEL_TDX"},
				Swnames:                  []string{"CONFIDENTIAL_SPACE"},
				ProjectIds:               []string{"staging"},
				ServiceAccounts:          []string{"workload@staging.iam.gserviceaccount.com"},
			},
		},
	}
	with := func(fn func(*linkedca.ACMERemoteAttestation)) *linkedca.ACMEProvisioner {
		d := proto.Clone(current).(*linkedca.ACMEProvisioner)
		fn(d.RemoteAttestation)
		return d
	}
	tests := []struct {
		name    string
		args    []string
		want    *linkedca.ACMEProvisioner
		wantErr string
	}{
		{"ok unchanged", nil, current, ""},
		{"ok other flag", []string{"--require-eab=false"}, func() *linkedca.ACMEProvisioner {
			d := proto.Clone(current).(*linkedca.ACMEProvisioner)
			d.RequireEab = false
			return d
		}(), ""},
		{"ok require false", []string{"--remote-attestation-require=false"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.Require = false }), ""},

		// Formats
		{"ok add format", []string{"--remote-attestation-format", "SEV-SNP"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.Formats = []string{"tdx", "confidential-space", "sev-snp"}
			}), ""},
		{"ok add existing format", []string{"--remote-attestation-format", "tdx"}, current, ""},
		{"ok remove format", []string{"--remove-remote-attestation-format", "confidential-space"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.Formats = []string{"tdx"} }), ""},
		{"ok replace format", []string{"--remove-remote-attestation-format", "tdx", "--remote-attestation-format", "sev-snp"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.Formats = []string{"confidential-space", "sev-snp"} }), ""},

		// Claims hint
		{"ok add claims hint", []string{"--remote-attestation-claims-hint", "measurements"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ClaimsHint = []string{"ueid", "measurements"} }), ""},
		{"ok remove claims hint", []string{"--remove-remote-attestation-claims-hint", "ueid"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ClaimsHint = nil }), ""},

		// Vendor roots
		{"ok tdx roots", []string{"--remote-attestation-tdx-roots", rootFile},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.TdxRoots = rootPEM }), ""},
		{"ok restore intel roots", []string{"--remote-attestation-tdx-roots="},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.TdxRoots = nil }), ""},
		{"ok sev-snp roots", []string{"--remote-attestation-sev-snp-roots", bundleFile},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.SevSnpRoots = bundlePEM }), ""},
		{"ok restore amd roots", []string{"--remote-attestation-sev-snp-roots="},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.SevSnpRoots = nil }), ""},

		// Confidential Space
		{"ok cs roots", []string{"--remote-attestation-cs-roots", rootFile},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Roots = rootPEM }), ""},
		{"ok clear cs roots", []string{"--remove-remote-attestation-format", "confidential-space", "--remote-attestation-cs-roots="},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.Formats = []string{"tdx"}
				ra.ConfidentialSpace.Roots = nil
			}), ""},
		{"ok cs audience", []string{"--remote-attestation-cs-audience", "rats"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Audience = "rats" }), ""},
		{"ok clear cs audience", []string{"--remote-attestation-cs-audience="},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Audience = "" }), ""},
		{"ok cs max token age", []string{"--remote-attestation-cs-max-token-age", "1m"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.MaxTokenAge = "1m" }), ""},
		{"ok clear cs max token age", []string{"--remote-attestation-cs-max-token-age="},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.MaxTokenAge = "" }), ""},
		{"ok add image digest", []string{"--remote-attestation-cs-image-digest", "sha256:bbbb"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.ImageDigests = []string{"sha256:aaaa", "sha256:bbbb"}
			}), ""},
		{"ok remove image digest", []string{"--remove-remote-attestation-cs-image-digest", "sha256:aaaa"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.ImageDigests = nil }), ""},
		{"ok add image signer key id", []string{"--remote-attestation-cs-image-signer-key-id", "key-2"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.ImageSignerKeyIds = []string{"key-1", "key-2"}
			}), ""},
		{"ok remove image signer key id", []string{"--remove-remote-attestation-cs-image-signer-key-id", "key-1"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.ImageSignerKeyIds = nil }), ""},
		{"ok add support attribute", []string{"--remote-attestation-cs-require-support-attribute", "USABLE"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.RequireSupportAttributes = []string{"STABLE", "USABLE"}
			}), ""},
		{"ok remove support attribute", []string{"--remove-remote-attestation-cs-require-support-attribute", "STABLE"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.RequireSupportAttributes = nil }), ""},
		{"ok add hwmodel", []string{"--remote-attestation-cs-hwmodel", "GCP_AMD_SEV"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.Hwmodels = []string{"GCP_INTEL_TDX", "GCP_AMD_SEV"}
			}), ""},
		{"ok remove hwmodel", []string{"--remove-remote-attestation-cs-hwmodel", "GCP_INTEL_TDX"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Hwmodels = nil }), ""},
		{"ok add swname", []string{"--remote-attestation-cs-swname", "OTHER"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.Swnames = []string{"CONFIDENTIAL_SPACE", "OTHER"}
			}), ""},
		{"ok remove swname", []string{"--remove-remote-attestation-cs-swname", "CONFIDENTIAL_SPACE"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Swnames = nil }), ""},
		{"ok replace project", []string{
			"--remove-remote-attestation-cs-project", "staging",
			"--remote-attestation-cs-project", "workloads",
		}, with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.ProjectIds = []string{"workloads"} }), ""},
		{"ok add existing project", []string{"--remote-attestation-cs-project", "staging"}, current, ""},
		{"ok add service account", []string{"--remote-attestation-cs-service-account", "workload@workloads.iam.gserviceaccount.com"},
			with(func(ra *linkedca.ACMERemoteAttestation) {
				ra.ConfidentialSpace.ServiceAccounts = []string{
					"workload@staging.iam.gserviceaccount.com",
					"workload@workloads.iam.gserviceaccount.com",
				}
			}), ""},
		{"ok remove service account", []string{"--remove-remote-attestation-cs-service-account", "workload@staging.iam.gserviceaccount.com"},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.ServiceAccounts = nil }), ""},

		{"fail format", []string{"--remote-attestation-format", "sgx"}, nil,
			"invalid value 'sgx' for flag '--remote-attestation-format'"},
		{"fail remove format", []string{"--remove-remote-attestation-format", "sgx"}, nil,
			"invalid value 'sgx' for flag '--remove-remote-attestation-format'; options are tdx, sev-snp, confidential-space"},
		{"fail empty claims hint", []string{"--remote-attestation-claims-hint="}, nil,
			"missing value for flag '--remote-attestation-claims-hint'"},
		{"fail max token age", []string{"--remote-attestation-cs-max-token-age", "-1m"}, nil,
			"invalid value '-1m' for flag '--remote-attestation-cs-max-token-age'; it must be a duration greater than 0"},
		{"fail cs roots without a certificate", []string{"--remote-attestation-cs-roots", keyFile}, nil,
			"error loading certificates from " + keyFile},
		{"ok clear cs roots in use", []string{"--remote-attestation-cs-roots="},
			with(func(ra *linkedca.ACMERemoteAttestation) { ra.ConfidentialSpace.Roots = nil }), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &linkedca.Provisioner{
				Type: linkedca.Provisioner_ACME,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{
					ACME: proto.Clone(current).(*linkedca.ACMEProvisioner),
				}},
			}
			err := updateACMEDetails(remoteAttestationCommandContext(t, updateCommand(), tt.args...), p)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Truef(t, proto.Equal(tt.want, p.Details.GetACME()), "got %v", p.Details.GetACME())
		})
	}
}

// TestUpdateACMEDetailsRemoteAttestationPresence checks that update creates the
// remote attestation configuration, and its Confidential Space configuration,
// when a flag sets a value, and removes either when the flags leave it empty.
func TestUpdateACMEDetailsRemoteAttestationPresence(t *testing.T) {
	tests := []struct {
		name    string
		current *linkedca.ACMERemoteAttestation
		args    []string
		want    *linkedca.ACMERemoteAttestation
	}{
		{"ok create", nil, []string{"--remote-attestation-cs-project", "workloads"},
			&linkedca.ACMERemoteAttestation{
				ConfidentialSpace: &linkedca.ACMEConfidentialSpace{ProjectIds: []string{"workloads"}},
			}},
		{"ok remove from nothing", nil, []string{
			"--remove-remote-attestation-format", "tdx",
			"--remove-remote-attestation-cs-project", "workloads",
		}, nil},
		{"ok clear from nothing", nil, []string{"--remote-attestation-cs-roots=", "--remote-attestation-require=false"}, nil},
		{"ok remove confidential space", &linkedca.ACMERemoteAttestation{
			Formats:           []string{"tdx"},
			ConfidentialSpace: &linkedca.ACMEConfidentialSpace{ProjectIds: []string{"workloads"}},
		}, []string{"--remove-remote-attestation-cs-project", "workloads"},
			&linkedca.ACMERemoteAttestation{Formats: []string{"tdx"}}},
		{"ok remove everything", &linkedca.ACMERemoteAttestation{
			Require:           true,
			ConfidentialSpace: &linkedca.ACMEConfidentialSpace{Audience: "rats"},
		}, []string{"--remote-attestation-require=false", "--remote-attestation-cs-audience="}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &linkedca.ACMEProvisioner{RemoteAttestation: tt.current}
			p := &linkedca.Provisioner{
				Type:    linkedca.Provisioner_ACME,
				Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{ACME: d}},
			}
			require.NoError(t, updateACMEDetails(remoteAttestationCommandContext(t, updateCommand(), tt.args...), p))
			if tt.want == nil {
				assert.Nil(t, d.RemoteAttestation)
				return
			}
			assert.Truef(t, proto.Equal(tt.want, d.RemoteAttestation), "got %v", d.RemoteAttestation)
		})
	}
}

func TestACMEChallengeRemoteAttest01(t *testing.T) {
	t.Run("validate", func(t *testing.T) {
		for _, args := range [][]string{
			{"--challenge", "remote-attest-01"},
			{"--challenge", "REMOTE-ATTEST-01"},
			{"--remove-challenge", "remote-attest-01"},
		} {
			ctx := remoteAttestationCommandContext(t, updateCommand(), args...)
			assert.NoError(t, validateChallengeFlag(ctx, linkedca.Provisioner_ACME), args)
		}
		ctx := remoteAttestationCommandContext(t, updateCommand(), "--challenge", "remote-attest-02")
		assert.EqualError(t, validateChallengeFlag(ctx, linkedca.Provisioner_ACME),
			"invalid value 'remote-attest-02' for flag '--challenge'; options are http-01, dns-01, tls-alpn-01, device-attest-01 and remote-attest-01")
	})

	t.Run("to linkedca", func(t *testing.T) {
		assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{
			linkedca.ACMEProvisioner_HTTP_01,
			linkedca.ACMEProvisioner_REMOTE_ATTEST_01,
		}, acmeChallengeToLinkedca([]string{"http-01", "Remote-Attest-01"}))
	})

	t.Run("update", func(t *testing.T) {
		d := &linkedca.ACMEProvisioner{
			Challenges: []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_DNS_01},
		}
		p := &linkedca.Provisioner{
			Type:    linkedca.Provisioner_ACME,
			Details: &linkedca.ProvisionerDetails{Data: &linkedca.ProvisionerDetails_ACME{ACME: d}},
		}
		ctx := remoteAttestationCommandContext(t, updateCommand(), "--challenge", "remote-attest-01")
		require.NoError(t, updateACMEDetails(ctx, p))
		assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{
			linkedca.ACMEProvisioner_DNS_01, linkedca.ACMEProvisioner_REMOTE_ATTEST_01,
		}, d.Challenges)

		ctx = remoteAttestationCommandContext(t, updateCommand(), "--remove-challenge", "remote-attest-01")
		require.NoError(t, updateACMEDetails(ctx, p))
		assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{linkedca.ACMEProvisioner_DNS_01}, d.Challenges)

		d.RemoteAttestation = &linkedca.ACMERemoteAttestation{Formats: []string{"confidential-space"}}
		ctx = remoteAttestationCommandContext(t, updateCommand(), "--challenge", "remote-attest-01")
		require.NoError(t, updateACMEDetails(ctx, p))
		assert.Equal(t, []linkedca.ACMEProvisioner_ChallengeType{
			linkedca.ACMEProvisioner_DNS_01, linkedca.ACMEProvisioner_REMOTE_ATTEST_01,
		}, d.Challenges)
	})

	// The ca.json client stores provisioners through these conversions, and
	// step ca provisioner list prints the certificates side.
	t.Run("through certificates", func(t *testing.T) {
		rootFile, _, _, rootPEM, _ := remoteAttestationTestFiles(t)
		details, err := createACMEDetails(remoteAttestationCommandContext(t, addCommand(),
			"--challenge", "remote-attest-01",
			"--remote-attestation-require",
			"--remote-attestation-format", "confidential-space",
			"--remote-attestation-claims-hint", "ueid",
			"--remote-attestation-tdx-roots", rootFile,
			"--remote-attestation-cs-roots", rootFile,
			"--remote-attestation-cs-max-token-age", "1m30s",
			"--remote-attestation-cs-project", "workloads",
		))
		require.NoError(t, err)

		p, err := authority.ProvisionerToCertificates(&linkedca.Provisioner{
			Type:    linkedca.Provisioner_ACME,
			Name:    "rats",
			Details: details,
		})
		require.NoError(t, err)
		acme, ok := p.(*provisioner.ACME)
		require.True(t, ok)
		assert.Equal(t, []provisioner.ACMEChallenge{provisioner.REMOTE_ATTEST_01}, acme.Challenges)
		require.NotNil(t, acme.RemoteAttestation)
		assert.True(t, acme.RemoteAttestation.Require)
		assert.Equal(t, rootPEM, acme.RemoteAttestation.TDXRoots)
		require.NotNil(t, acme.RemoteAttestation.ConfidentialSpace)
		assert.Equal(t, rootPEM, acme.RemoteAttestation.ConfidentialSpace.Roots)
		assert.Equal(t, []string{"workloads"}, acme.RemoteAttestation.ConfidentialSpace.ProjectIDs)

		back, err := authority.ProvisionerToLinkedca(p)
		require.NoError(t, err)
		assert.Truef(t, proto.Equal(details.GetACME(), back.Details.GetACME()), "got %v", back.Details.GetACME())
	})
}
