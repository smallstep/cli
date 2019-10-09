#########################################
# Building Docker Image
#
# Builds a dockerfile for step by building a linux version of the step-cli and
# then copying the specific binary when building the container.
#
# This ensures the container is as small as possible without having to deal
# with getting access to private repositories inside the container during build
# time.
#########################################

# XXX We put the output for the build in 'output' so we don't mess with how we
# do rule overriding from the base Makefile (if you name it 'build' it messes up
# the wildcarding).
DOCKER_OUTPUT=$(OUTPUT_ROOT)docker/

DOCKER_MAKE=V=$V GOOS_OVERRIDE='GOOS=linux GOARCH=amd64' PREFIX=$(1) make $(1)bin/$(2)
DOCKER_BUILD=$Q docker build -t smallstep/$(1):latest -f docker/$(2) --build-arg BINPATH=$(DOCKER_OUTPUT)bin/step .

docker: docker-make docker/Dockerfile.step-cli
	$(call DOCKER_BUILD,step-cli,Dockerfile.step-cli)

docker-make:
	mkdir -p $(DOCKER_OUTPUT)
	$(call DOCKER_MAKE,$(DOCKER_OUTPUT),step)

.PHONY: docker docker-make

#################################################
# Releasing Docker Images
#
# Using the docker build infrastructure, this section is responsible for
# logging into docker hub and pushing the built docker containers up with the
# appropriate tags.
#################################################

DOCKER_TAG=docker tag smallstep/$(1):latest smallstep/$(1):$(2)
DOCKER_PUSH=docker push smallstep/$(1):$(2)

docker-tag:
	$(call DOCKER_TAG,step-cli,$(VERSION))

docker-push-tag: docker-tag
	$(call DOCKER_PUSH,step-cli,$(VERSION))

docker-push-tag-latest:
	$(call DOCKER_PUSH,step-cli,latest)

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-tag docker-push-tag docker-push-tag-latest docker-login

#################################################
# Targets for different type of builds
#################################################

# For all builds we build the docker container
docker-master: docker

# For all builds with a release candidate tag
docker-release-candidate: docker-master docker-login docker-push-tag

# For all builds of a release tag
docker-release: docker-release-candidate docker-push-tag-latest

.PHONY: docker-master docker-release-candidate docker-release
