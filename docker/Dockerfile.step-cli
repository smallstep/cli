FROM alpine

ARG BINPATH="bin/step"

ENV STEP="/home/step"
ENV STEPPATH="/home/step"
ENV STEPDEBUG="1"

RUN apk add --no-cache bash curl \
        && addgroup -g 1000 step \
        && adduser -D -u 1000 -G step step

COPY $BINPATH "/usr/local/bin/step"

USER step
WORKDIR /home/step

STOPSIGNAL SIGTERM

CMD /bin/bash
