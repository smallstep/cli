package integration

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/smallstep/cli/internal/cmd"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"step": func() {
			// Trust only the local OIDC fixture in these test subprocesses,
			// without modifying the machine's trust store.
			if root := os.Getenv("STEP_TEST_OIDC_ROOT"); root != "" {
				pem, err := os.ReadFile(root)
				if err != nil {
					panic(err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					panic("invalid OIDC fixture root")
				}
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
				http.DefaultTransport = transport
			}
			cmd.Run()
		},
	})
}
