module github.com/smallstep/cli

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/ThomasRooney/gexpect v0.0.0-20161231170123-5482f0350944
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/fatih/color v1.8.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20191227052852-215e87163ea7 // indirect
	github.com/golang/mock v1.3.1 // indirect
	github.com/golangci/gocyclo v0.0.0-20180528144436-0a533e8fa43d // indirect
	github.com/golangci/golangci-lint v1.22.2 // indirect
	github.com/golangci/revgrep v0.0.0-20180812185044-276a5c0a1039 // indirect
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/monologue v0.0.0-20191220140058-35abc9683a6c // indirect
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/gostaticanalysis/analysisutil v0.0.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.12.1 // indirect
	github.com/icrowley/fake v0.0.0-20180203215853-4178557ae428
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/manifoldco/promptui v0.3.1
	github.com/olekukonko/tablewriter v0.0.4 // indirect
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/pquerna/otp v1.0.0
	github.com/prometheus/client_golang v1.3.0 // indirect
	github.com/samfoo/ansi v0.0.0-20160124022901-b6bd2ded7189
	github.com/securego/gosec v0.0.0-20200106085552-9cb83e10afad // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/smallstep/assert v0.0.0-20200103212524-b99dc1097b15
	github.com/smallstep/certificates v0.14.0-rc.1.0.20191218224459-1fa35491ea07
	github.com/smallstep/certinfo v1.0.0
	github.com/smallstep/truststore v0.9.3
	github.com/smallstep/zcrypto v0.0.0-20191122194514-76530dff70e7
	github.com/smallstep/zlint v0.0.0-20180727184541-d84eaafe274f
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.22.2
	go.etcd.io/etcd v3.3.18+incompatible // indirect
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20191227163750-53104e6ec876
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	golang.org/x/sys v0.0.0-20200106162015-b016eb3dc98e
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.0.0-20200106190116-7be0a674c9fc // indirect
	google.golang.org/genproto v0.0.0-20191230161307-f3c370f40bfb // indirect
	google.golang.org/grpc v1.26.0 // indirect
	gopkg.in/ini.v1 v1.51.1 // indirect
	gopkg.in/square/go-jose.v2 v2.4.0
	mvdan.cc/unparam v0.0.0-20191111180625-960b1ec0f2c2 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
	sourcegraph.com/sqs/pbtypes v1.0.0 // indirect
)

//replace github.com/smallstep/certificates => ../certificates
