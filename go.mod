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
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/manifoldco/promptui v0.3.1
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/certificates v0.16.0-rc.1.0.20201021053511-711aafc1d552
	github.com/smallstep/certinfo v1.4.0
	github.com/smallstep/truststore v0.9.6
	github.com/smallstep/zcrypto v0.0.0-20200203191936-fbc32cf76bce
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.5.1
	github.com/urfave/cli v1.22.2
	go.step.sm/crypto v0.6.1
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	golang.org/x/sys v0.0.0-20200828194041-157a740278f4
	google.golang.org/grpc/examples v0.0.0-20201013205100-7745e521ff61 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	software.sslmate.com/src/go-pkcs12 v0.0.0-20200830195227-52f69702a001
)

// replace github.com/smallstep/certificates => ../certificates
// replace github.com/smallstep/certinfo => ../certinfo
// replace go.step.sm/crypto => ../crypto
