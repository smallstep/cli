#!/usr/bin/env bash

set -e

FILE="${1}"
PACKAGE="${2}"
VERSION="${3}"

echo "Package File: ${FILE}"
echo "Package: ${PACKAGE}"
echo "Version: ${VERSION}"
echo "Release: ${RELEASE}"
echo "Location: ${GCLOUD_LOCATION}"

if [ "${FILE: -4}" == ".deb" ]; then
  gcloud storage cp ${FILE} gs://artifacts-outgoing/${PACKAGE}/deb/${VERSION}/
else
  gcloud storage cp ${FILE} gs://artifacts-outgoing/${PACKAGE}/rpm/${VERSION}/
fi
