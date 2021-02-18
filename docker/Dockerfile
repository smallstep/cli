FROM alpine

ENV STEP="/home/step"
ENV STEPPATH="/home/step"
ARG STEPUID=1000
ARG STEPGID=1000

RUN apk add --no-cache bash curl \
        && addgroup -g ${STEPGID} step \
        && adduser -D -u ${STEPUID} -G step step \
        && chown step:step /home/step

COPY step "/usr/local/bin/step"

USER step
WORKDIR /home/step

STOPSIGNAL SIGTERM

CMD /bin/bash
