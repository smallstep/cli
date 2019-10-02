package ssh

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func proxyCommand() cli.Command {
	return cli.Command{
		Name:      "proxy",
		Action:    command.ActionFunc(proxyAction),
		Usage:     "proxy connections through an ssh tunnel",
		UsageText: `**step ssh proxy** <subject> <address>`,
		Description: `**step ssh proxy** proxies connections through an ssh tunnel.

## POSITIONAL ARGUMENTS

<ubject>
:  Subject of the key or certificate to use.

## EXAMPLES

`,
		Flags: []cli.Flag{
			sshConnectFlag,
			cli.StringFlag{
				Name:  "L",
				Usage: "Proxies to the local server the remote TCP or Unix socket connection.",
			},
			cli.StringFlag{
				Name:  "R",
				Usage: "Proxies to a remote server the local TCP or Unix socket connection.",
			},
			sshBastionFlag,
			sshBastionCommandFlag,
			sshProxyFlag,
		},
	}
}

func proxyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	// Arguments
	args := ctx.Args()
	subject := args[0]
	address := args[1]
	user := provisioner.SanitizeSSHUserPrincipal(subject)

	// Flags:
	proxyCommand := ctx.String("proxy")
	bastionAddress := ctx.String("bastion")
	bastionCommand := ctx.String("bastion-command")

	local := ctx.String("L")
	remote := ctx.String("R")
	if local == "" && remote == "" {
		return errs.RequiredOrFlag(ctx, "L", "R")
	}

	// Connect with SSH agent
	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}

	signer, err := agent.GetSigner(subject)
	if err != nil {
		if err == sshutil.ErrNotFound {
			return errors.Errorf("certificate for %s was not found, please run:\nstep ssh login %s", subject, subject)
		}
		return err
	}

	// Use signer to connect to the remote server
	opts := []sshutil.ShellOption{
		sshutil.WithSigner(signer),
	}
	if proxyCommand != "" {
		opts = append(opts, sshutil.WithProxyCommand(proxyCommand))
	}
	if bastionAddress != "" {
		opts = append(opts, sshutil.WithBastion(user, bastionAddress, bastionCommand))
	}

	shell, err := sshutil.NewShell(user, address, opts...)
	if err != nil {
		return err
	}

	wg := new(sync.WaitGroup)
	errCh := make(chan error, 1)
	if local != "" {
		go func() {
			wg.Add(1)
			bindNetwork, bindAddress, hostNetwork, hostAddress, err := parseForward(ctx, "L")
			if err != nil {
				errCh <- err
				return
			}
			fmt.Printf("Serving %s locally on %s ...\n", bindNetwork, bindAddress)
			errCh <- shell.LocalForward(bindNetwork, bindAddress, hostNetwork, hostAddress)
		}()
	}

	if remote != "" {
		go func() {
			wg.Add(1)
			bindNetwork, bindAddress, hostNetwork, hostAddress, err := parseForward(ctx, "R")
			if err != nil {
				errCh <- err
				return
			}
			if hostAddress == "" {
				errCh <- errors.New("remote SOCKS 4/5 proxy is not yet supported")
				return
			}

			fmt.Printf("Serving %s remotely on %s ...\n", bindNetwork, bindAddress)
			errCh <- shell.RemoteForward(bindNetwork, bindAddress, hostNetwork, hostAddress)
		}()
	}

	wg.Wait()
	return <-errCh
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func makeAddress(host, port string) string {
	switch host {
	case "":
		return "localhost:" + port
	case "*":
		return "0.0.0.0:" + port
	default:
		return host + ":" + port
	}
}

func parseForward(ctx *cli.Context, flag string) (bindNetwork, bindAddress, hostNetwork, hostAddress string, err error) {
	value := ctx.String(flag)
	parts := strings.Split(value, ":")
	switch len(parts) {
	case 1:
		switch {
		// -R port -> SOCKS 4/5 server
		case flag == "R" && isNumber(parts[0]):
			bindNetwork = "tcp"
			bindAddress = makeAddress("", parts[0])
		default:
			err = errs.InvalidFlagValue(ctx, flag, value, "")
		}
	case 2:
		switch {
		// -L port:remote_socket
		// -R port:local_socket
		case isNumber(parts[0]):
			bindNetwork = "tcp"
			bindAddress = makeAddress("", parts[0])
			hostNetwork = "unix"
			hostAddress = parts[1]
		// -R bind_address:port -> SOCKS 4/5 server
		case flag == "R" && isNumber(parts[1]):
			bindNetwork = "tcp"
			bindAddress = makeAddress(parts[0], parts[1])

		// -L local_socket:remote_socket
		// -R remote_socket:local_socket
		default:
			bindNetwork = "unix"
			bindAddress = parts[0]
			hostAddress = "unix"
			hostNetwork = parts[1]
		}
	case 3:
		switch {
		// -L port:host:host_port
		case isNumber(parts[0]) && isNumber(parts[2]):
			bindNetwork = "tcp"
			bindAddress = makeAddress("", parts[0])
			hostNetwork = "tcp"
			hostAddress = makeAddress(parts[1], parts[2])
		// -L bind_address:port:remote_socket
		// -R bind_address:port:local_socket
		case isNumber(parts[1]):
			bindNetwork = "tcp"
			bindAddress = makeAddress(parts[0], parts[1])
			hostNetwork = "unix"
			hostAddress = parts[2]
		// -L local_socket:host:host_port
		// -R remote_socket:host:host_port
		case isNumber(parts[2]):
			bindNetwork = "unix"
			bindAddress = parts[0]
			hostNetwork = "tcp"
			hostAddress = makeAddress(parts[1], parts[2])
		default:
			err = errs.InvalidFlagValue(ctx, flag, value, "")
		}
	case 4:
		// -L bind_address:port:host:host_port
		// -R bind_address:port:host:host_port
		bindNetwork = "tcp"
		bindAddress = makeAddress(parts[0], parts[1])
		hostNetwork = "tcp"
		hostAddress = makeAddress(parts[2], parts[3])
	default:
		err = errs.InvalidFlagValue(ctx, flag, value, "")
	}

	return
}
