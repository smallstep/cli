#########################################
# Building Docker Image
#
# This uses a multi-stage build file. The first stage is a builder (that might
# be large in size). After the build has succeeded, the statically linked
# binary is copied to a new image that is optimized for size.
#########################################

docker-prepare:
	# Ensure, we can build for ARM architecture
	[ -f /proc/sys/fs/binfmt_misc/qemu-arm ] || docker run --rm --privileged docker/binfmt:a7996909642ee92942dcd6cff44b9b95f08dad64

	# Register buildx builder
	mkdir -p $$HOME/.docker/cli-plugins

	wget -O $$HOME/.docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.3.1/buildx-v0.3.1.linux-amd64
	chmod +x $$HOME/.docker/cli-plugins/docker-buildx

	$$HOME/.docker/cli-plugins/docker-buildx create --name mybuilder --platform amd64 --platform arm || true
	$$HOME/.docker/cli-plugins/docker-buildx use mybuilder

.PHONY: docker-prepare

#################################################
# Releasing Docker Images
#
# Using the docker build infrastructure, this section is responsible for
# logging into docker hub.
#################################################

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-login

#################################################
# Targets for different type of builds
#################################################

DOCKER_IMAGE_NAME = smallstep/cli
PLATFORMS = --platform amd64 --platform 386 --platform arm

# For all builds we build the docker container
docker-master: docker-prepare
	$$HOME/.docker/cli-plugins/docker-buildx build . --progress plain -t $(DOCKER_IMAGE_NAME):latest -f docker/Dockerfile $(PLATFORMS)

# For all builds with a release candidate tag
docker-release-candidate: docker-prepare docker-login
	$$HOME/.docker/cli-plugins/docker-buildx build . --progress plain -t $(DOCKER_IMAGE_NAME):$(VERSION) -f docker/Dockerfile $(PLATFORMS) --push

# For all builds of a release tag
docker-release: docker-prepare docker-login
	$$HOME/.docker/cli-plugins/docker-buildx build . --progress plain -t $(DOCKER_IMAGE_NAME):latest -f docker/Dockerfile $(PLATFORMS) --push

.PHONY: docker-master docker-release-candidate docker-release
