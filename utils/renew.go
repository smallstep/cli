package utils

import (
	"crypto/x509"
	"math/rand"
	"time"
)

func NextRenewDuration(leaf *x509.Certificate, expiresIn, renewPeriod time.Duration) time.Duration {
	if renewPeriod > 0 {
		// Renew now if it will be expired in renewPeriod
		if (time.Until(leaf.NotAfter) - renewPeriod) <= 0 {
			return 0
		}
		return renewPeriod
	}

	period := leaf.NotAfter.Sub(leaf.NotBefore)
	if expiresIn == 0 {
		expiresIn = period / 3
	}

	switch d := time.Until(leaf.NotAfter) - expiresIn; {
	case d <= 0:
		return 0
	case d < period/20:
		return time.Duration(rand.Int63n(int64(d)))
	default:
		n := rand.Int63n(int64(period / 20))
		d -= time.Duration(n)
		return d
	}
}
