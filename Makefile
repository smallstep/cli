all: build lint test

.PHONY: all

-include make/common.mk
-include make/docker.mk
