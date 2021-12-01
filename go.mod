module github.com/smallstep/cli

go 1.16

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/corpix/uarand v0.1.1 // indirect
	github.com/google/uuid v1.3.0
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/manifoldco/promptui v0.9.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/certificates v0.18.0
	github.com/smallstep/certinfo v1.5.2
	github.com/smallstep/truststore v0.9.6
	github.com/smallstep/zcrypto v0.0.0-20210924233136-66c2600f6e71
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.5
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	go.step.sm/cli-utils v0.7.0
	go.step.sm/crypto v0.13.0
	go.step.sm/linkedca v0.7.0
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272
	golang.org/x/net v0.0.0-20210913180222-943fd674d43e
	golang.org/x/sys v0.0.0-20211031064116-611d5d643895
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.6.0
	software.sslmate.com/src/go-pkcs12 v0.0.0-20201103104416-57fc603b7f52
)

// replace github.com/smallstep/certificates => ../certificates

// replace github.com/smallstep/certinfo => ../certinfo
// replace go.step.sm/linkedca => ../linkedca

// replace go.step.sm/cli-utils => ../cli-utils

// replace go.step.sm/crypto => ../crypto
