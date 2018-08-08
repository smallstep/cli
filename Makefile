PKG=github.com/smallstep/cli/cmd/step
BINNAME=step

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE?=

# Set shell to bash for `echo -e`
SHELL:=/bin/bash

all: build lint test

.PHONY: all

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q which dep || go get github.com/golang/dep/cmd/dep
	$Q dep ensure

vendor: Gopkg.lock
	$Q dep ensure

BOOTSTRAP=\
	github.com/golang/lint/golint \
	github.com/client9/misspell/cmd/misspell \
	github.com/gordonklaus/ineffassign \
	github.com/tsenart/deadcode \
	github.com/alecthomas/gometalinter

define VENDOR_BIN_TMPL
vendor/bin/$(notdir $(1)): vendor
	$Q go build -o $$@ ./vendor/$(1)
VENDOR_BINS += vendor/bin/$(notdir $(1))
endef

$(foreach pkg,$(BOOTSTRAP),$(eval $(call VENDOR_BIN_TMPL,$(pkg))))

.PHONY: bootstrap vendor

#########################################
# Build
#########################################

# Version flags to embed in the binaries
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
GOFLAGS := CGO_ENABLED=0

build: $(PREFIX)bin/$(BINNAME)
	@echo "Build Complete!"

$(PREFIX)bin/$(BINNAME): vendor $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)

# Target for building without calling dep ensure
simple:
	$Q mkdir -p bin/
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o bin/$(BINNAME) $(LDFLAGS) $(PKG)
	@echo "Build Complete!"

.PHONY: build simple

#########################################
# Go generate
#########################################

generate:
	$Q go generate ./...

.PHONY: generate

#########################################
# Test
#########################################
test:
	$Q $(GOFLAGS) go test -short -cover ./...

vtest:
	$(Q)for d in $$(go list ./... | grep -v vendor); do \
    echo -e "TESTS FOR: for \033[0;35m$$d\033[0m"; \
    $(GOFLAGS) go test -v -bench=. -run=. -short -coverprofile=profile.coverage.out -covermode=atomic $$d; \
	out=$$?; \
	if [[ $$out -ne 0 ]]; then ret=$$out; fi;\
    rm -f profile.coverage.out; \
	done; exit $$ret;

.PHONY: test vtest

integrate: integration

integration: bin/$(BINNAME)
	$Q $(GOFLAGS) go test -tags=integration ./integration/...

.PHONY: integrate integration

#########################################
# Linting
#########################################

LINTERS=\
	gofmt \
	golint \
	vet \
	misspell \
	ineffassign \
	deadcode

$(patsubst %,%-bin,$(filter-out gofmt vet,$(LINTERS))): %-bin: vendor/bin/%
gofmt-bin vet-bin:

$(LINTERS): %: vendor/bin/gometalinter %-bin vendor
	$Q PATH=`pwd`/vendor/bin:$$PATH gometalinter --tests --disable-all --vendor \
	     --deadline=5m -s data -s pkg --enable $@ ./...
fmt:
	$Q gofmt -l -w $(SRC)

lint: $(LINTERS)

.PHONY: $(LINTERS) lint fmt

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/local

install: bin/$(BINNAME)
	$Q install -D bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Debian
#########################################

debian:
	$Q PREFIX=/usr dpkg-buildpackage -b -rfakeroot -us -uc

distclean: clean

.PHONY: debian distclean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

OUTPUT_ROOT=output/
BINARY_OUTPUT=$(OUTPUT_ROOT)binary/
BUNDLE_MAKE=v=$v GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2)' PREFIX=$(3) make $(3)bin/step

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,$(BINARY_OUTPUT)linux/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,$(BINARY_OUTPUT)darwin/)

define BUNDLE
	$(q)BUNDLE_DIR=$(BINARY_OUTPUT)$(1)/bundle; \
	stepName=step_$(2); \
 	mkdir -p $$BUNDLE_DIR; \
	TMP=$$(mktemp -d $$BUNDLE_DIR/tmp.XXXX); \
	trap "rm -rf $$TMP" EXIT INT QUIT TERM; \
	newdir=$$TMP/$$stepName; \
	mkdir -p $$newdir/bin; \
	cp $(BINARY_OUTPUT)$(1)/bin/step $$newdir/bin/; \
	cp README.md $$newdir/; \
	NEW_BUNDLE=$$BUNDLE_DIR/$$stepName-$(1)-$(3).tar.gz; \
	rm -f $$NEW_BUNDLE; \
    tar -zcvf $$NEW_BUNDLE -C $$TMP $$stepName; \
	cp $$NEW_BUNDLE $$BUNDLE_DIR/step_latest-$(1)-$(3).tar.gz;
endef

bundle-linux: binary-linux
	$(call BUNDLE,linux,$(VERSION),amd64)

bundle-darwin: binary-darwin
	$(call BUNDLE,darwin,$(VERSION),amd64)

#################################################
# Upload statically compiled step binary for various operating systems
#################################################

# http://tmont.com/blargh/2014/1/uploading-to-s3-in-bash
define AWS_UPLOAD
	$(Q)fn="smallstep_$(1)-$(2)-$(3).tar.gz"; \
	resource="/$(4)/$$fn"; \
	contentType="application/x-compressed-tar"; \
	dateValue=$$(date -R); \
	access="x-amz-acl:public-read"; \
	stringToSign="PUT\n\n$$contentType\n$$dateValue\n$$access\n$$resource"; \
	signature=$$(echo -en $$stringToSign | openssl sha1 -hmac $(AWS_SECRET_ACCESS_KEY) -binary | base64); \
	curl -X PUT -T $(BINARY_OUTPUT)$(2)/bundle/$$fn \
	  -H "Host: $(4).s3.amazonaws.com" \
	  -H "Date: $$dateValue" \
	  -H "Content-Type: $$contentType" \
	  -H "Authorization: AWS $(AWS_ACCESS_KEY_ID):$$signature" \
	  -H "x-amz-acl: public-read" \
	  https://$(4).s3.amazonaws.com/$$fn
endef

AWS_BUCKET=smallstep-downloads

upload-linux-tag: bundle-linux
	$(call AWS_UPLOAD,$(VERSION),linux,amd64,$(AWS_BUCKET))

upload-linux-latest: bundle-linux
	$(call AWS_UPLOAD,latest,linux,amd64,$(AWS_BUCKET))

upload-darwin-tag: bundle-darwin
	$(call AWS_UPLOAD,$(VERSION),darwin,amd64,$(AWS_BUCKET))

upload-darwin-latest: bundle-darwin
	$(call AWS_UPLOAD,latest,darwin,amd64,$(AWS_BUCKET))

upload-tag: upload-linux-tag upload-darwin-tag

upload-latest: upload-linux-latest upload-linux-tag upload-darwin-latest upload-darwin-tag

#################################################
# Targets for uploading the step binary
#################################################

# For all builds that are not tagged
upload-push-master:

# For all builds on the master branch with an rc tag
upload-push-release-candidate: upload-tag

# For all builds on the master branch with a release tag
upload-push-prod-release: upload-push-release-candidate upload-latest

# This command is called by travis directly *after* a successful build
upload-push: upload-push-$(PUSHTYPE)

.PHONY: upload-push-release-candidate upload-push-prod-release upload-push

#########################################
# Clean
#########################################

clean:
	@echo "You will need to run 'make bootstrap' or 'dep ensure' directly to re-download any dependencies."
	$Q rm -rf vendor
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif

.PHOMY: clean
