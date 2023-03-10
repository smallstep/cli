//go:build windows

package ca

import (
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"log"
	"os"
	"time"
)

type windowsRenewer struct {
	eLog                         *eventlog.Log
	next, expiresIn, renewPeriod time.Duration
	afterRenew                   func() error
	renewer                      *renewer
	outFile                      string
}

func (r *renewer) Service(outFile string, next, expiresIn, renewPeriod time.Duration, afterRenew func() error) error {
	errLog := log.New(os.Stderr, "ERROR: ", log.LstdFlags)
	inService, err := svc.IsWindowsService()
	if err != nil {
		errLog.Fatalf("failed to determine if we are running in service: %v", err)
	}

	if !inService {
		errLog.Fatalf("--service requires running as a service, see step ca renew --help for an example of how to install the service")
	}

	eventlog.InstallAsEventCreate("step-renew", eventlog.Info|eventlog.Warning|eventlog.Error)

	// Loggers
	eLog, err := eventlog.Open("step-renew")
	if err != nil {
		return err
	}
	defer eLog.Close()

	wr := windowsRenewer{
		eLog:        eLog,
		next:        next,
		expiresIn:   expiresIn,
		renewPeriod: renewPeriod,
		afterRenew:  afterRenew,
		renewer:     r,
		outFile:     outFile,
	}

	eLog.Info(100, fmt.Sprintf("starting step certificate renewal service. First renewal in %s", next.Round(time.Second)))

	return svc.Run("step-renew", &wr)
}

func (wr *windowsRenewer) Execute(args []string, cr <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	var err error
	changes <- svc.Status{State: svc.StartPending}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		select {
		case <-time.After(wr.next):
			if wr.next, err = wr.renewer.RenewAndPrepareNext(wr.outFile, wr.expiresIn, wr.renewPeriod); err != nil {
				wr.eLog.Warning(1, err.Error())
			} else if err := wr.afterRenew(); err != nil {
				wr.eLog.Warning(1, err.Error())
			}
		case c := <-cr:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				wr.eLog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}
