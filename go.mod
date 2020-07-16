module github.com/smallstep/cli

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/google/uuid v1.1.1
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/juju/ansiterm v0.0.0-20180109212912-720a0952cc2a // indirect
	github.com/lunixbochs/vtclean v1.0.0 // indirect
	github.com/manifoldco/promptui v0.3.1
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200103212524-b99dc1097b15
	github.com/smallstep/certificates v0.14.5
	github.com/smallstep/certinfo v1.3.0
	github.com/smallstep/truststore v0.9.6
	github.com/smallstep/zcrypto v0.0.0-20200203191936-fbc32cf76bce
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.5.1
	github.com/urfave/cli v1.22.2
	golang.org/x/crypto v0.0.0-20200323165209-0ec3e9974c59
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/sys v0.0.0-20200106162015-b016eb3dc98e
	gopkg.in/square/go-jose.v2 v2.4.0
)

//replace github.com/smallstep/certificates => ../certificates
//replace github.com/smallstep/certinfo => ../certinfo
