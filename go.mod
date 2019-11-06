module github.com/smallstep/cli

go 1.13

require (
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/boombuler/barcode v1.0.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/go-chi/chi v4.0.2+incompatible // indirect
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/juju/ansiterm v0.0.0-20180109212912-720a0952cc2a // indirect
	github.com/lunixbochs/vtclean v1.0.0 // indirect
	github.com/manifoldco/promptui v0.3.1
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.10 // indirect
	github.com/newrelic/go-agent v2.15.0+incompatible // indirect
	github.com/pkg/errors v0.8.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v0.0.0-20170918181015-86672fcb3f95
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/smallstep/assert v0.0.0-20180720014142-de77670473b5
	github.com/smallstep/certificates v0.14.0-rc.1.0.20191106004142-a9ea292bd480
	github.com/smallstep/certinfo v0.0.0-20191029235839-00563809d483
	github.com/smallstep/truststore v0.9.3
	github.com/smallstep/zcrypto v0.0.0-20191030000234-ab27e7ba0886
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.20.1-0.20181029213200-b67dcf995b6a
	github.com/weppos/publicsuffix-go v0.10.0 // indirect
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859
	gopkg.in/square/go-jose.v2 v2.4.0
	howett.net/plist v0.0.0-20181124034731-591f970eefbb // indirect
)

replace github.com/smallstep/certificates => ../certificates
