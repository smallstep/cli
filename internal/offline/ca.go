package offline

import (
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	caclient "github.com/smallstep/cli/utils/cautils/client"
	"github.com/urfave/cli"
)

type CA interface {
	caclient.CaClient

	VerifyClientCert(certFile, keyFile string) error
	GenerateToken(ctx *cli.Context, tokType int, subject string, sans []string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error)
}
