//go:build !js
// +build !js

package renewer

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (r *Renewer) Daemon(outFile string, next, expiresIn, renewPeriod time.Duration, afterRenew func() error) error {
	// Loggers
	Info := log.New(os.Stdout, "INFO: ", log.LstdFlags)
	Error := log.New(os.Stderr, "ERROR: ", log.LstdFlags)

	// Daemon loop
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	//signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	Info.Printf("first renewal in %s", next.Round(time.Second))
	var err error
	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				if next, err = r.RenewAndPrepareNext(outFile, expiresIn, renewPeriod); err != nil {
					Error.Println(err)
				} else if err := afterRenew(); err != nil {
					Error.Println(err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				return nil
			}
		case <-time.After(next):
			if next, err = r.RenewAndPrepareNext(outFile, expiresIn, renewPeriod); err != nil {
				Error.Println(err)
			} else if err := afterRenew(); err != nil {
				Error.Println(err)
			}
		}
	}
}
