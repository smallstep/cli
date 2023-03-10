FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum .
RUN go mod download
COPY . .

ARG TARGETOS TARGETARCH
RUN apk add --no-cache make git curl && \
	cd /src && \
	mkdir -p output/bin && \
	CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o bin/step github.com/smallstep/cli/cmd/step

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
