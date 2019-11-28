module github.com/smallstep/cli

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/manifoldco/promptui v0.3.1
	github.com/pkg/errors v0.8.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v0.0.0-20170918181015-86672fcb3f95
	github.com/smallstep/assert v0.0.0-20180720014142-de77670473b5
	github.com/smallstep/certificates v0.14.0-rc.1.0.20191128013006-b25cbbe6caa1
	github.com/smallstep/certinfo v0.0.0-20191029235839-00563809d483
	github.com/smallstep/truststore v0.9.3
	github.com/smallstep/zcrypto v0.0.0-20191122194514-76530dff70e7
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.20.1-0.20181029213200-b67dcf995b6a
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859
	golang.org/x/sys v0.0.0-20191008105621-543471e840be
	gopkg.in/square/go-jose.v2 v2.4.0
)

// replace github.com/smallstep/certificates => ../certificates
