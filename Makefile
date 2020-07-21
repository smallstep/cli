all: lint test build

.PHONY: all

#################################################
# Determine the type of `push` and `version`
#################################################

# If TRAVIS_TAG is set then we know this ref has been tagged.
ifdef TRAVIS_TAG
VERSION := $(TRAVIS_TAG)
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
VERSION := $(or $(VERSION),$(shell ./.version.sh .VERSION))
	ifeq ($(TRAVIS_BRANCH),master)
PUSHTYPE := master
	else
PUSHTYPE := branch
	endif
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')

ifdef V
$(info    TRAVIS_TAG is $(TRAVIS_TAG))
$(info    VERSION is $(VERSION))
$(info    PUSHTYPE is $(PUSHTYPE))
endif

include make/common.mk
include make/docker.mk

#########################################
# Debian
#########################################

changelog:
	$Q echo "step-cli ($(VERSION)) unstable; urgency=medium" > debian/changelog
	$Q echo >> debian/changelog
	$Q echo "  * See https://github.com/smallstep/cli/releases" >> debian/changelog
	$Q echo >> debian/changelog
	$Q echo " -- Smallstep Labs, Inc. <techadmin@smallstep.com>  $(shell date -uR)" >> debian/changelog

debian: changelog
	$Q set -e; mkdir -p $(RELEASE); \
	OUTPUT=../step-cli_*.deb; \
	rm -f $$OUTPUT; \
	dpkg-buildpackage -b -rfakeroot -us -uc && cp $$OUTPUT $(RELEASE)/

distclean: clean

.PHONY: changelog debian distclean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

BINARY_OUTPUT=$(OUTPUT_ROOT)binary/
RELEASE=./.travis-releases

define BUNDLE_MAKE
	$(q) GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2) GOARM=$(3)' PREFIX=$(4) make $(4)bin/step
endef

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,,$(BINARY_OUTPUT)linux/)

binary-linux-arm64:
	$(call BUNDLE_MAKE,linux,arm64,,$(BINARY_OUTPUT)linux.arm64/)

binary-linux-armv7:
	$(call BUNDLE_MAKE,linux,arm,7,$(BINARY_OUTPUT)linux.armv7/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,,$(BINARY_OUTPUT)darwin/)

binary-windows:
	$(call BUNDLE_MAKE,windows,amd64,,$(BINARY_OUTPUT)windows/)

define BUNDLE
	# $(1) -- Binary Output Dir Name
	# $(2) -- Step Platform Name
	# $(3) -- Step Binary Architecture
	# $(4) -- Step Binary Name (For Windows Comaptibility)
	$(q) ./make/bundle.sh "$(BINARY_OUTPUT)$(1)" "$(RELEASE)" "$(VERSION)" "$(2)" "$(3)" "$(4)"
endef

bundle-linux: binary-linux binary-linux-arm64 binary-linux-armv7
	$(call BUNDLE,linux,linux,amd64,step)
	$(call BUNDLE,linux.arm64,linux,arm64,step)
	$(call BUNDLE,linux.armv7,linux,armv7,step)

bundle-darwin: binary-darwin
	$(call BUNDLE,darwin,darwin,amd64,step)

bundle-windows: binary-windows
	$(call BUNDLE,windows,windows,amd64,step.exe)

.PHONY: binary-linux binary-darwin binary-windows bundle-linux bundle-darwin bundle-windows

#################################################
# Targets for creating OS specific artifacts and archives
#################################################

artifacts-linux-tag: bundle-linux debian

artifacts-darwin-tag: bundle-darwin

artifacts-windows-tag: bundle-windows

artifacts-archive-tag:
	$Q mkdir -p $(RELEASE)
	$Q git archive v$(VERSION) | gzip > $(RELEASE)/step-cli_$(VERSION).tar.gz

artifacts-tag: artifacts-linux-tag artifacts-darwin-tag artifacts-windows-tag artifacts-archive-tag

.PHONY: artifacts-linux-tag artifacts-darwin-tag artifacts-windows-tag artifacts-archive-tag artifacts-tag

#################################################
# Targets for creating step artifacts
#################################################
#
# For all builds that are not tagged and not on the master branch.
artifacts-branch:

# For all builds on the master branch (or PRs targeting the master branch) that
# are not tagged.
artifacts-master:

# For all builds with a release candidate tag.
artifacts-release-candidate: artifacts-tag

# For all builds with a release tag.
artifacts-release: artifacts-tag

# This command is called by travis directly *after* a successful build
artifacts: artifacts-$(PUSHTYPE) docker-$(PUSHTYPE)

.PHONY: artifacts-master artifacts-release-candidate artifacts-release artifacts
