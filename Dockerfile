FROM python:3.14-alpine

ARG BUILD_VERSION="1.0.0-snapshot"
ARG PROJECT_NAME=
ARG BUILD_SHA=
ARG BUILD_DATE=
ARG BUILD_REF=

ENV APP_VERSION=${BUILD_VERSION}
ENV APP_BUILD_DATE=${BUILD_DATE}
ENV APP_BUILD_REF=${BUILD_REF}
ENV APP_BUILD_SHA=${BUILD_SHA}

LABEL VERSION="${BUILD_VERSION}"
LABEL PROJECT_NAME="${PROJECT_NAME}"


COPY . /app

RUN \
  apk update && \
  pip install --upgrade pip && \
  pip install -r /app/setup/requirements.txt && \
  rm -rf /app/setup && \
  rm -rf /var/cache/apk/*

VOLUME ["/config"]
WORKDIR /app

CMD ["python", "-u", "/app/main.py"]
