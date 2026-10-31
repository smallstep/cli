package provisioner

import (
	"encoding/pem"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/proto"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/internal/sliceutil"
)

// ACME provisioner flags for the remote-attest-01 challenge. The CA uses them
// only when the challenge is enabled with --challenge remote-attest-01.
var (
	remoteAttestationRequireFlag = cli.BoolFlag{
		Name: "remote-attestation-require",
		Usage: `Require remote attestation for every certificate of an ACME provisioner: an
order without a remote-attestation identifier gets one, so it cannot be
finalized without remote-attest-01 evidence. Use
'--remote-attestation-require=false' to stop requiring it.`,
	}
	remoteAttestationFormatFlag = cli.StringSliceFlag{
		Name: "remote-attestation-format",
		Usage: `The evidence <format> accepted by the remote-attest-01 challenge of an ACME
provisioner: "tdx" for an Intel TDX quote, "sev-snp" for an AMD SEV-SNP
attestation report, or "confidential-space" for a Google Cloud Confidential
Space token. Use the flag multiple times to accept multiple formats. It
defaults to tdx and sev-snp, and to confidential-space too when Confidential
Space is configured.`,
	}
	removeRemoteAttestationFormatFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-format",
		Usage: `Remove an evidence <format> accepted by the remote-attest-01 challenge of an
ACME provisioner. Use the flag multiple times to remove multiple formats.`,
	}
	remoteAttestationClaimsHintFlag = cli.StringSliceFlag{
		Name: "remote-attestation-claims-hint",
		Usage: `A <claim> sent to clients in the attestClaimsHint of remote-attest-01
challenges, a hint of what the evidence should carry. Use the flag multiple
times to send multiple claims.`,
	}
	removeRemoteAttestationClaimsHintFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-claims-hint",
		Usage: `Remove a <claim> sent to clients in the attestClaimsHint of remote-attest-01
challenges. Use the flag multiple times to remove multiple claims.`,
	}
	remoteAttestationTDXRootsFlag = cli.StringFlag{
		Name: "remote-attestation-tdx-roots",
		Usage: `PEM-formatted root certificate(s) <file> that replace Intel's SGX root CA as
the root of the TDX PCK certificate chains of remote-attest-01 evidence, for
tests or a CA that cannot use Intel's. An empty value restores Intel's.`,
	}
	remoteAttestationSEVSNPRootsFlag = cli.StringFlag{
		Name: "remote-attestation-sev-snp-roots",
		Usage: `PEM-formatted AMD ARK, ASK and ASVK certificate(s) <file> that replace AMD's
as the roots of the SEV-SNP endorsement keys of remote-attest-01 evidence, for
tests or a CA that cannot use AMD's. An empty value restores AMD's.`,
	}

	// Confidential Space flags.
	remoteAttestationCSRootsFlag = cli.StringFlag{
		Name: "remote-attestation-cs-roots",
		Usage: `PEM-formatted root certificate(s) <file> that replace the root of Google
Cloud Attestation's PKI, which signs Confidential Space tokens and which step-ca
embeds, for tests. An empty value restores Google's.`,
	}
	remoteAttestationCSAudienceFlag = cli.StringFlag{
		Name: "remote-attestation-cs-audience",
		Usage: `The <audience> Confidential Space tokens must have been requested for. It
defaults to the ACME directory URL of the provisioner; an empty value restores
the default.`,
	}
	remoteAttestationCSMaxTokenAgeFlag = cli.StringFlag{
		Name: "remote-attestation-cs-max-token-age",
		Usage: `The maximum age of a Confidential Space token, a <duration> measured from its
iat claim. It defaults to 5m; an empty value restores the default.`,
	}
	remoteAttestationCSImageDigestFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-image-digest",
		Usage: `A container image <digest> a Confidential Space workload may run, compared
with the submods.container.image_digest claim. Use the flag multiple times to
allow multiple images.`,
	}
	removeRemoteAttestationCSImageDigestFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-image-digest",
		Usage: `Remove a container image <digest> a Confidential Space workload may run. Use
the flag multiple times to remove multiple images.`,
	}
	remoteAttestationCSImageSignerKeyIDFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-image-signer-key-id",
		Usage: `The key <id> of a signature the image of a Confidential Space workload may
carry, compared with the key_id of the submods.container.image_signatures
claim. If image digests are also set, matching either is enough. Use the flag
multiple times to allow multiple keys.`,
	}
	removeRemoteAttestationCSImageSignerKeyIDFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-image-signer-key-id",
		Usage: `Remove the key <id> of a signature the image of a Confidential Space workload
may carry. Use the flag multiple times to remove multiple keys.`,
	}
	remoteAttestationCSRequireSupportAttributeFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-require-support-attribute",
		Usage: `A support <attribute> the submods.confidential_space.support_attributes claim
of a Confidential Space token must include, for example STABLE. Use the flag
multiple times to require multiple attributes.`,
	}
	removeRemoteAttestationCSRequireSupportAttributeFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-require-support-attribute",
		Usage: `Remove a support <attribute> Confidential Space tokens must include. Use the
flag multiple times to remove multiple attributes.`,
	}
	remoteAttestationCSHWModelFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-hwmodel",
		Usage: `A hardware <model> a Confidential Space workload may run on, compared with
the hwmodel claim, for example GCP_INTEL_TDX. Use the flag multiple times to
allow multiple models.`,
	}
	removeRemoteAttestationCSHWModelFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-hwmodel",
		Usage: `Remove a hardware <model> a Confidential Space workload may run on. Use the
flag multiple times to remove multiple models.`,
	}
	remoteAttestationCSSWNameFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-swname",
		Usage: `A software <name> a Confidential Space workload may run on, compared with the
swname claim, for example CONFIDENTIAL_SPACE. Use the flag multiple times to
allow multiple names.`,
	}
	removeRemoteAttestationCSSWNameFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-swname",
		Usage: `Remove a software <name> a Confidential Space workload may run on. Use the
flag multiple times to remove multiple names.`,
	}
	remoteAttestationCSProjectFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-project",
		Usage: `The <id> of a Google Cloud project a Confidential Space workload may run in,
compared with the submods.gce.project_id claim. Use the flag multiple times to
allow multiple projects.`,
	}
	removeRemoteAttestationCSProjectFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-project",
		Usage: `Remove the <id> of a Google Cloud project a Confidential Space workload may
run in. Use the flag multiple times to remove multiple projects.`,
	}
	remoteAttestationCSServiceAccountFlag = cli.StringSliceFlag{
		Name: "remote-attestation-cs-service-account",
		Usage: `The <email> of a Google Cloud service account a Confidential Space workload
may run as; the google_service_accounts claim must include one of them. Use
the flag multiple times to allow multiple service accounts.`,
	}
	removeRemoteAttestationCSServiceAccountFlag = cli.StringSliceFlag{
		Name: "remove-remote-attestation-cs-service-account",
		Usage: `Remove the <email> of a Google Cloud service account a Confidential Space
workload may run as. Use the flag multiple times to remove multiple service
accounts.`,
	}
)

var (
	// remoteAttestationCSFlags are the flags that configure Confidential Space.
	remoteAttestationCSFlags = []cli.Flag{
		remoteAttestationCSRootsFlag,
		remoteAttestationCSAudienceFlag,
		remoteAttestationCSMaxTokenAgeFlag,
		remoteAttestationCSImageDigestFlag,
		removeRemoteAttestationCSImageDigestFlag,
		remoteAttestationCSImageSignerKeyIDFlag,
		removeRemoteAttestationCSImageSignerKeyIDFlag,
		remoteAttestationCSRequireSupportAttributeFlag,
		removeRemoteAttestationCSRequireSupportAttributeFlag,
		remoteAttestationCSHWModelFlag,
		removeRemoteAttestationCSHWModelFlag,
		remoteAttestationCSSWNameFlag,
		removeRemoteAttestationCSSWNameFlag,
		remoteAttestationCSProjectFlag,
		removeRemoteAttestationCSProjectFlag,
		remoteAttestationCSServiceAccountFlag,
		removeRemoteAttestationCSServiceAccountFlag,
	}

	// remoteAttestationFlags are all the flags that configure remote-attest-01.
	remoteAttestationFlags = append([]cli.Flag{
		remoteAttestationRequireFlag,
		remoteAttestationFormatFlag,
		removeRemoteAttestationFormatFlag,
		remoteAttestationClaimsHintFlag,
		removeRemoteAttestationClaimsHintFlag,
		remoteAttestationTDXRootsFlag,
		remoteAttestationSEVSNPRootsFlag,
	}, remoteAttestationCSFlags...)
)

// remoteAttestationFormats are the values of --remote-attestation-format.
var remoteAttestationFormats = []string{"tdx", "sev-snp", "confidential-space"}

// updateRemoteAttestation applies the remote attestation flags to the given
// ACME provisioner details. It creates the remote attestation configuration,
// and its Confidential Space configuration, when one of their flags is set,
// and removes either if the flags leave it empty.
func updateRemoteAttestation(ctx *cli.Context, d *linkedca.ACMEProvisioner) error {
	if !isAnySet(ctx, remoteAttestationFlags) {
		return nil
	}
	if d.RemoteAttestation == nil {
		d.RemoteAttestation = &linkedca.ACMERemoteAttestation{}
	}
	ra := d.RemoteAttestation

	if ctx.IsSet("remote-attestation-require") {
		ra.Require = ctx.Bool("remote-attestation-require")
	}

	if ctx.IsSet("remove-remote-attestation-format") {
		formats, err := parseRemoteAttestationFormats(ctx, "remove-remote-attestation-format")
		if err != nil {
			return err
		}
		ra.Formats = sliceutil.RemoveValues(ra.Formats, formats)
	}
	if ctx.IsSet("remote-attestation-format") {
		formats, err := parseRemoteAttestationFormats(ctx, "remote-attestation-format")
		if err != nil {
			return err
		}
		ra.Formats = sliceutil.RemoveDuplicates(append(ra.Formats, formats...))
	}

	if err := updateRemoteAttestationList(ctx, "remote-attestation-claims-hint", &ra.ClaimsHint); err != nil {
		return err
	}

	var err error
	if ctx.IsSet("remote-attestation-tdx-roots") {
		if ra.TdxRoots, err = readRemoteAttestationRoots(ctx.String("remote-attestation-tdx-roots")); err != nil {
			return err
		}
	}
	if ctx.IsSet("remote-attestation-sev-snp-roots") {
		if ra.SevSnpRoots, err = readRemoteAttestationRoots(ctx.String("remote-attestation-sev-snp-roots")); err != nil {
			return err
		}
	}

	if err := updateConfidentialSpace(ctx, ra); err != nil {
		return err
	}

	if proto.Size(ra) == 0 {
		d.RemoteAttestation = nil
	}
	return nil
}

// updateConfidentialSpace applies the Confidential Space flags to the given
// remote attestation configuration.
func updateConfidentialSpace(ctx *cli.Context, ra *linkedca.ACMERemoteAttestation) error {
	if !isAnySet(ctx, remoteAttestationCSFlags) {
		return nil
	}
	if ra.ConfidentialSpace == nil {
		ra.ConfidentialSpace = &linkedca.ACMEConfidentialSpace{}
	}
	cs := ra.ConfidentialSpace

	if ctx.IsSet("remote-attestation-cs-roots") {
		roots, err := readRemoteAttestationRoots(ctx.String("remote-attestation-cs-roots"))
		if err != nil {
			return err
		}
		cs.Roots = roots
	}
	if ctx.IsSet("remote-attestation-cs-audience") {
		cs.Audience = ctx.String("remote-attestation-cs-audience")
	}
	if ctx.IsSet("remote-attestation-cs-max-token-age") {
		v := ctx.String("remote-attestation-cs-max-token-age")
		if v != "" {
			if dur, err := time.ParseDuration(v); err != nil || dur <= 0 {
				return errs.InvalidFlagValueMsg(ctx, "remote-attestation-cs-max-token-age", v, "it must be a duration greater than 0")
			}
		}
		cs.MaxTokenAge = v
	}

	for _, l := range []struct {
		flag   string
		values *[]string
	}{
		{"remote-attestation-cs-image-digest", &cs.ImageDigests},
		{"remote-attestation-cs-image-signer-key-id", &cs.ImageSignerKeyIds},
		{"remote-attestation-cs-require-support-attribute", &cs.RequireSupportAttributes},
		{"remote-attestation-cs-hwmodel", &cs.Hwmodels},
		{"remote-attestation-cs-swname", &cs.Swnames},
		{"remote-attestation-cs-project", &cs.ProjectIds},
		{"remote-attestation-cs-service-account", &cs.ServiceAccounts},
	} {
		if err := updateRemoteAttestationList(ctx, l.flag, l.values); err != nil {
			return err
		}
	}

	if proto.Size(cs) == 0 {
		ra.ConfidentialSpace = nil
	}
	return nil
}

// updateRemoteAttestationList removes the values of the --remove- variant of
// the given flag from a list, then adds the values of the flag, which cannot
// be empty.
func updateRemoteAttestationList(ctx *cli.Context, flag string, list *[]string) error {
	if ctx.IsSet("remove-" + flag) {
		*list = sliceutil.RemoveValues(*list, ctx.StringSlice("remove-"+flag))
	}
	if ctx.IsSet(flag) {
		values := ctx.StringSlice(flag)
		for _, v := range values {
			if v == "" {
				return errs.InvalidFlagValue(ctx, flag, v, "")
			}
		}
		*list = sliceutil.RemoveDuplicates(append(*list, values...))
	}
	return nil
}

// parseRemoteAttestationFormats returns the formats named by a format flag, in
// the lower case the CA expects.
func parseRemoteAttestationFormats(ctx *cli.Context, flag string) ([]string, error) {
	values := ctx.StringSlice(flag)
	formats := make([]string, 0, len(values))
	for _, v := range values {
		format := strings.ToLower(v)
		if !slices.Contains(remoteAttestationFormats, format) {
			return nil, errs.InvalidFlagValue(ctx, flag, v, strings.Join(remoteAttestationFormats, ", "))
		}
		formats = append(formats, format)
	}
	return formats, nil
}

// readRemoteAttestationRoots reads the certificates in a PEM bundle and returns
// them as one PEM bundle, as linkedca stores remote attestation roots. An
// empty file name returns no roots.
func readRemoteAttestationRoots(file string) ([]byte, error) {
	if file == "" {
		return nil, nil
	}
	certs, err := pemutil.ReadCertificateBundle(file)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading certificates from %s", file)
	}
	var roots []byte
	for _, cert := range certs {
		roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return roots, nil
}

// isAnySet reports whether any of the given flags is set.
func isAnySet(ctx *cli.Context, flags []cli.Flag) bool {
	for _, f := range flags {
		if ctx.IsSet(f.GetName()) {
			return true
		}
	}
	return false
}
