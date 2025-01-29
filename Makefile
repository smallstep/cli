# Run `make bootstrap` to set up your local environment.
# To build using go, use `make build`
# For a binary that's in parity with how our CI system builds,
# run `make goreleaser` to build using GoReleaser Pro.

# Variables:
# V=1 for verbose output.

# the name of the executable
BINNAME?=step

# the build output path
PREFIX?=bin

# the install path
DESTDIR?=/usr/local/bin

# GOOS_OVERRIDE="GOOS=linux GOARCH=arm GOARM=6" to change OS and arch
GOOS_OVERRIDE?=

# CGO_OVERRIDE="CGO_ENABLED=1" to enable CGO
CGO_OVERRIDE?=CGO_ENABLED=0

# which build id in .goreleaser.yml to build
GORELEASER_BUILD_ID?=default

# all go files
SRC=$(shell find . -type f -name '*.go')

all: lint test build

ci: test build

.PHONY: all ci

#################################################
# Determine the type of `push` and `version`
#################################################

ifdef GITHUB_REF
VERSION ?= $(shell echo $(GITHUB_REF) | sed 's/^refs\/tags\///')
NOT_RC  := $(shell echo $(VERSION) | grep -v -e -rc)
	ifeq ($(NOT_RC),)
PUSHTYPE := release-candidate
	else
PUSHTYPE := release
	endif
else
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
# If we are not in an active git dir then try reading the version from .VERSION.
# .VERSION contains a slug populated by `git archive`.
VERSION := $(or $(VERSION),$(shell make/version.sh .VERSION))
PUSHTYPE := branch
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')

ifdef V
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
$(info    PUSHTYPE is $(PUSHTYPE))
endif

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
ifdef DEBUG
	LDFLAGS := -ldflags='-X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
	GCFLAGS := -gcflags "all=-N -l"
else
	LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
	GCFLAGS :=
endif

Q=$(if $V,,@)
SRC=$(shell find . -type f -name '*.go')
OUTPUT_ROOT=output/

ifeq ($(OS),Windows_NT)
	HOSTOS=Windows
else
	HOSTOS=$(shell uname)
endif
HOSTARCH=$(shell go env GOHOSTARCH)

GORELEASER_PRO_URL=https://github.com/goreleaser/goreleaser-pro/releases/latest/download/goreleaser-pro_$(HOSTOS)_$(HOSTARCH).tar.gz

.PHONY: all

#########################################
# Bootstrapping
#########################################
TMPDIR := $(shell mktemp -d)
bootstra%: GOPATH=$(shell go env GOPATH)
bootstra%:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest
	$Q go install golang.org/x/tools/cmd/goimports@latest
	@echo "Installing GoReleaser Pro into $(GOPATH)/bin"
	$Q curl -o $(TMPDIR)/goreleaser.tar.gz -L $(GORELEASER_PRO_URL)
	$Q ls $(TMPDIR)
	$Q tar xvzf $(TMPDIR)/goreleaser.tar.gz -C $(TMPDIR)
	$Q cp $(TMPDIR)/goreleaser $(GOPATH)/bin

.PHONY: bootstra%

#########################################
# Build
#########################################

build: $(PREFIX)/$(BINNAME)
	@echo "Build Complete!"

$(PREFIX)/$(BINNAME): $(SRC)
	$Q mkdir -p $(PREFIX)
	$Q $(GOOS_OVERRIDE) $(CGO_OVERRIDE) go build \
		-v \
	   	-o $(PREFIX)/$(BINNAME) \
		$(GCFLAGS) $(LDFLAGS) \
	   	github.com/smallstep/cli/cmd/step

goreleaser:
	$Q mkdir -p $(PREFIX)
	$Q $(GOOS_OVERRIDE) $(CGO_OVERRIDE) DEBUG=$(DEBUG) goreleaser build \
		--id $(GORELEASER_BUILD_ID) \
	   	--snapshot \
		--single-target \
	   	--clean \
		--output $(PREFIX)/$(BINNAME)

.PHONY: build goreleaser


#########################################
# Test
#########################################

test:
	$Q $(CGO_OVERRIDE) $(GOFLAGS) gotestsum -- -coverprofile=coverage.out -short -covermode=atomic ./...

race:
	$Q $(CGO_OVERRIDE) $(GOFLAGS) gotestsum -- -race ./...

.PHONY: test race

integrate: integration

integration: build
	$Q $(CGO_OVERRIDE) gotestsum -- -tags=integration ./integration/...

.PHONY: integrate integration

#########################################
# Linting
#########################################

fmt:
	$Q goimports -local github.com/golangci/golangci-lint -l -w $(SRC)

lint: golint govulncheck

golint: SHELL:=/bin/bash
golint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m

govulncheck:
	$Q govulncheck ./...

.PHONY: fmt lint golint govulncheck

#########################################
# Install
#########################################

install: $(PREFIX)/$(BINNAME)
	$Q mkdir -p $(DESTDIR)/
	$Q install $(PREFIX)/$(BINNAME) $(DESTDIR)/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)/$(BINNAME)

.PHONY: install uninstall

#########################################
# Clean
#########################################

clean:
	$Q rm -f $(PREFIX)/$(BINNAME)
	$Q rm -rf dist

.PHONY: clean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

BINARY_OUTPUT=$(OUTPUT_ROOT)binary/

define BUNDLE_MAKE
	# $(1) -- Go Operating System (e.g. linux, darwin, windows, etc.)
	# $(2) -- Go Architecture (e.g. amd64, arm, arm64, etc.)
	# $(3) -- Go ARM architectural family (e.g. 7, 8, etc.)
	# $(4) -- Parent directory for executables generated by 'make'.
	$Q GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2) GOARM=$(3)' PREFIX=$(4) make $(4)/$(BINNAME)
endef

binary-linux-amd64:
	$(call BUNDLE_MAKE,linux,amd64,,$(BINARY_OUTPUT)linux-amd64)

binary-linux-arm64:
	$(call BUNDLE_MAKE,linux,arm64,,$(BINARY_OUTPUT)linux-arm64)

binary-linux-armv7:
	$(call BUNDLE_MAKE,linux,arm,7,$(BINARY_OUTPUT)linux-armv7)

binary-linux-mips:
	$(call BUNDLE_MAKE,linux,mips,,$(BINARY_OUTPUT)linux-mips)

binary-darwin-amd64:
	$(call BUNDLE_MAKE,darwin,amd64,,$(BINARY_OUTPUT)darwin-amd64)

binary-darwin-arm64:
	$(call BUNDLE_MAKE,darwin,amd64,,$(BINARY_OUTPUT)darwin-arm64)

binary-windows-amd64:
	$(call BUNDLE_MAKE,windows,amd64,,$(BINARY_OUTPUT)windows-amd64)

.PHONY: binary-linux-amd64 binary-linux-arm64 binary-linux-armv7 binary-linux-mips binary-darwin-amd64 binary-darwin-arm64 binary-windows-amd64
