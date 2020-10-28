module github.com/smallstep/cli

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/boombuler/barcode v1.0.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/corpix/uarand v0.1.1 // indirect
	github.com/google/uuid v1.1.2
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/juju/ansiterm v0.0.0-20180109212912-720a0952cc2a // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/lunixbochs/vtclean v1.0.0 // indirect
	github.com/manifoldco/promptui v0.3.1
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/certificates v0.16.0-rc.2.0.20201028022356-33878218d012
	github.com/smallstep/certinfo v1.5.0
	github.com/smallstep/truststore v0.9.6
	github.com/smallstep/zcrypto v0.0.0-20200203191936-fbc32cf76bce
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli v1.22.4
	go.step.sm/crypto v0.7.0
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201021035429-f5854403a974
	golang.org/x/sys v0.0.0-20201022201747-fb209a7c41cd
	google.golang.org/grpc/examples v0.0.0-20201013205100-7745e521ff61 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	software.sslmate.com/src/go-pkcs12 v0.0.0-20200830195227-52f69702a001
)

// replace github.com/smallstep/certificates => ../certificates
// replace github.com/smallstep/certinfo => ../certinfo
// replace go.step.sm/crypto => ../crypto
