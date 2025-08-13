//go:build !windows

package ca

func (r *renewer) Service(outFile string, next, expiresIn, renewPeriod time.Duration, afterRenew func() error) error {
	errLog := log.New(os.Stderr, "ERROR: ", log.LstdFlags)
	errLog.Fatalf("running as a service is only supported on windows, use --daemon instead.")
}
