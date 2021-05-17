module github.com/smallstep/cli

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/boombuler/barcode v1.0.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/corpix/uarand v0.1.1 // indirect
	github.com/golangci/golangci-lint v1.24.0 // indirect
	github.com/google/uuid v1.1.2
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/manifoldco/promptui v0.8.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.0.0
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/certificates v0.15.14
	github.com/smallstep/certinfo v1.5.0
	github.com/smallstep/truststore v0.9.6
	github.com/smallstep/zcrypto v0.0.0-20200203191936-fbc32cf76bce
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli v1.22.4
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1
	go.step.sm/crypto v0.8.3
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	software.sslmate.com/src/go-pkcs12 v0.0.0-20201103104416-57fc603b7f52
)

// This is a temporal workaround to fix a dependency problem between etcd and
// gRPC. The gRPC v1.29.1 supports old and new interfaces, so it can be used by
// packages using the old (go.etcd.io/etcd) and new (cloud.google.com)
// interfaces.
//
// For more information see https://github.com/etcd-io/etcd/issues/12124
replace google.golang.org/grpc => google.golang.org/grpc v1.29.1

replace github.com/smallstep/certificates => ../certificates

// replace github.com/smallstep/certinfo => ../certinfo
// replace go.step.sm/crypto => ../crypto
