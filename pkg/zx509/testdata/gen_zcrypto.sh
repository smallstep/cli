#!/bin/bash

# Copyright 2017 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This script generates extra test certificates not in the Golang X.509 stdlib
# package. It writes copy/pastable output to out/zcrypto_roots_test.go, which
# can be appended to verify_test.go.

# It generates the following certificates:
#
# - A root valid from 2017-01-01 to 2027-01-01
# - An intermediate (signed by the root) valid from 2020-01-01 to 2026-12-31
# - A leaf (signed by intermediate) with reversed NotBefore/NotAfter
#    + NotBefore: 2022-01-01
#    + NotAFter: 2021-01-01
# - A leaf (signed by intermediate) that is valid in a window before the
#   intermediate: 2018-01-01 to 2019-01-01

set -e

rm -rf out
mkdir out

GO_TEST_FILE=out/zcrypto_roots_test.go

ROOT_KEY_PATH=out/root.key
ROOT_REQ_PATH=out/root.req
ROOT_CERT_PATH=out/root.pem

INTERMEDIATE_KEY_PATH=out/intermediate.key
INTERMEDIATE_REQ_PATH=out/intermediate.req
INTERMEDIATE_CERT_PATH=out/intermediate.pem

LEAF_NEVER_VALID_KEY_PATH=out/leaf-never-valid.key
LEAF_NEVER_VALID_REQ_PATH=out/leaf-never-valid.req
LEAF_NEVER_VALID_CERT_PATH=out/leaf-never-valid.pem

LEAF_BEFORE_INTERMEDIATE_KEY_PATH=out/leaf-before-intermediate.key
LEAF_BEFORE_INTERMEDIATE_REQ_PATH=out/leaf-before-intermediate.req
LEAF_BEFORE_INTERMEDIATE_CERT_PATH=out/leaf-before-intermediate.pem

openssl genrsa -out $ROOT_KEY_PATH 2048
openssl genrsa -out $INTERMEDIATE_KEY_PATH 2048
openssl genrsa -out $LEAF_NEVER_VALID_KEY_PATH 2048
openssl genrsa -out $LEAF_BEFORE_INTERMEDIATE_KEY_PATH 2048

touch out/root.index
touch out/intermediate.index
echo "00" > out/root.serial
echo "FF" > out/intermediate.serial

# Create a self-signed root certificate request
SUBJECT_NAME="root_subject" \
openssl req \
  -new \
  -key $ROOT_KEY_PATH \
  -out $ROOT_REQ_PATH \
  -extensions root_extensions \
  -config ca.cnf

# Create the self-signed root from the request
openssl ca \
  -selfsign \
  -config ca.cnf \
  -name root_ca \
  -keyfile $ROOT_KEY_PATH \
  -startdate 170101000000Z \
  -enddate 270101000000Z \
  -extensions root_extensions \
  -in $ROOT_REQ_PATH \
  -out $ROOT_CERT_PATH \
  -batch

# Create the req for the intermediate certificate
SUBJECT_NAME="intermediate_subject" \
openssl req \
  -new \
  -key $INTERMEDIATE_KEY_PATH \
  -out $INTERMEDIATE_REQ_PATH \
  -extensions intermediate_extensions \
  -config ca.cnf

# Sign the interemediate certificate
openssl ca \
  -config ca.cnf \
  -name root_ca \
  -keyfile $ROOT_KEY_PATH \
  -cert $ROOT_CERT_PATH \
  -startdate 200101000000Z \
  -enddate 261231000000Z \
  -extensions intermediate_extensions \
  -in $INTERMEDIATE_REQ_PATH \
  -out $INTERMEDIATE_CERT_PATH \
  -batch

# Create a request for the never-valid leaf
SUBJECT_NAME="leaf_never_valid" \
openssl req \
  -new \
  -key $LEAF_NEVER_VALID_KEY_PATH \
  -out $LEAF_NEVER_VALID_REQ_PATH \
  -extensions leaf_extensions \
  -config ca.cnf

# Sign the never-valid leaf with the intermediate. Set NotAfter before
# NotBefore.
openssl ca \
  -config ca.cnf \
  -name intermediate_ca \
  -keyfile $INTERMEDIATE_KEY_PATH \
  -cert $INTERMEDIATE_CERT_PATH \
  -out $LEAF_NEVER_VALID_CERT_PATH \
  -in $LEAF_NEVER_VALID_REQ_PATH \
  -extensions leaf_extensions \
  -startdate 220101010000Z \
  -enddate 210101010000Z \
  -batch

# Create a request for the valid-before-intermediate leaf
SUBJECT_NAME="leaf_never_valid" \
openssl req \
  -new \
  -key $LEAF_BEFORE_INTERMEDIATE_KEY_PATH \
  -out $LEAF_BEFORE_INTERMEDIATE_REQ_PATH \
  -extensions leaf_extensions \
  -config ca.cnf

# Sign the leaf with an intermediate whose validity begins after the leaf
# expires.
openssl ca \
  -config ca.cnf \
  -name intermediate_ca \
  -keyfile $INTERMEDIATE_KEY_PATH \
  -cert $INTERMEDIATE_CERT_PATH \
  -out $LEAF_BEFORE_INTERMEDIATE_CERT_PATH \
  -in $LEAF_BEFORE_INTERMEDIATE_REQ_PATH \
  -extensions leaf_extensions \
  -startdate 180101010000Z \
  -enddate 190101010000Z \
  -batch

echo 'const zcryptoRoot = `' >> $GO_TEST_FILE
cat $ROOT_CERT_PATH >> $GO_TEST_FILE
echo '`' >> $GO_TEST_FILE

echo 'const zcryptoIntermediate = `' >> $GO_TEST_FILE
cat $INTERMEDIATE_CERT_PATH >> $GO_TEST_FILE
echo '`' >> $GO_TEST_FILE

echo 'const zcryptoNeverValid = `' >> $GO_TEST_FILE
cat $LEAF_NEVER_VALID_CERT_PATH >> $GO_TEST_FILE
echo '`' >> $GO_TEST_FILE

echo 'const zcryptoValidBeforeIntermediate = `' >> $GO_TEST_FILE
cat $LEAF_BEFORE_INTERMEDIATE_CERT_PATH >> $GO_TEST_FILE
echo '`' >> $GO_TEST_FILE
