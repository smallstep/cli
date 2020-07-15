FROM golang:alpine AS builder

RUN mkdir /src
ADD . /src

RUN apk add --no-cache make git curl && \
	cd /src && \
	mkdir -p output/bin && \
	make V=1 bin/step

FROM alpine

ENV STEP="/home/step"
ENV STEPPATH="/home/step"
ARG STEPUID=1000
ARG STEPGID=1000

RUN apk add --no-cache bash curl \
        && addgroup -g ${STEPGID} step \
        && adduser -D -u ${STEPUID} -G step step \
        && chown step:step /home/step

COPY --from=builder /src/bin/step "/usr/local/bin/step"

USER step
WORKDIR /home/step

STOPSIGNAL SIGTERM

CMD /bin/bash
