FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum .
RUN go mod download
COPY . .
RUN apk add --no-cache make git curl

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS="${TARGETOS}"; \
    GOARCH="${TARGETARCH}"; \
    if [ "${TARGETARCH}" = "arm" ] && [ "${TARGETVARIANT}" ]; then \
    GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 GOOS_OVERRIDE="GOOS=${GOOS} GOARCH=${GOARCH} GOARM=${GOARM}" \
    make V=1 bin/step

FROM alpine

ENV STEP="/home/step"
ENV STEPPATH="/home/step"
ARG STEPUID=1000
ARG STEPGID=1000

RUN apk update \
        && apk upgrade \
        && apk add --no-cache bash curl tzdata \
        && addgroup -g ${STEPGID} step \
        && adduser -D -u ${STEPUID} -G step step \
        && chown step:step /home/step

COPY --from=builder /src/bin/step "/usr/local/bin/step"

USER step
WORKDIR /home/step

STOPSIGNAL SIGTERM

CMD /bin/bash
