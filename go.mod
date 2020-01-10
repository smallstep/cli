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
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200103212524-b99dc1097b15
	github.com/smallstep/certificates v0.14.0-rc.1.0.20200110185849-085ae821636e
	github.com/smallstep/certinfo v1.0.0
	github.com/smallstep/truststore v0.9.3
	github.com/smallstep/zcrypto v0.0.0-20191122194514-76530dff70e7
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.22.2
	golang.org/x/crypto v0.0.0-20191227163750-53104e6ec876
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	golang.org/x/sys v0.0.0-20200106162015-b016eb3dc98e
	gopkg.in/square/go-jose.v2 v2.4.0
)

//replace github.com/smallstep/certificates => ../certificates
