#!/bin/sh

OPENSSL="/usr/local/Cellar/openssl@1.1/1.1.1-pre8/bin/openssl"
SSH_KEYGEN="/usr/bin/ssh-keygen"

#######################################
# PKCS#8                              #
#######################################

# EC
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out pkcs8/openssl.p256.pem
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve -out pkcs8/openssl.p384.pem
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve -out pkcs8/openssl.p521.pem

# Ed25519
$OPENSSL genpkey -outform PEM -algorithm ED25519 -out pkcs8/openssl.ed25519.pem

# RSA
$OPENSSL genpkey -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out pkcs8/openssl.rsa2048.pem
$OPENSSL genpkey -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out pkcs8/openssl.rsa4096.pem

# Public
NAMES="p256 p384 p521 ed25519 rsa2048 rsa4096"
for name in $NAMES
do
	$OPENSSL pkey -outform PEM -in "pkcs8/openssl.$name.pem" -pubout -out "pkcs8/openssl.$name.pub.pem"
done

# Encrypted
$OPENSSL pkey -outform PEM -in pkcs8/openssl.p256.pem -aes-128-cbc -passout pass:mypassword  -out pkcs8/openssl.p256.enc.pem
$OPENSSL pkey -outform PEM -in pkcs8/openssl.ed25519.pem -aes-192-cbc -passout pass:mypassword  -out pkcs8/openssl.ed25519.enc.pem
$OPENSSL pkey -outform PEM -in pkcs8/openssl.rsa2048.pem -aes-256-cbc -passout pass:mypassword  -out pkcs8/openssl.rsa2048.enc.pem
$OPENSSL pkey -outform PEM -in pkcs8/openssl.p384.pem -des -passout pass:mypassword -out pkcs8/openssl.p384.enc.pem
$OPENSSL pkey -outform PEM -in pkcs8/openssl.p521.pem -des3 -passout pass:mypassword -out pkcs8/openssl.p521.enc.pem

# Ed25519 DER
$OPENSSL pkey -outform DER -in pkcs8/openssl.ed25519.pem -out pkcs8/openssl.ed25519.der
$OPENSSL pkey -outform DER -in pkcs8/openssl.ed25519.pem -pubout -out pkcs8/openssl.ed25519.pub.der

#######################################
# PKCS#1                              #
#######################################

$OPENSSL genrsa -out openssl.rsa1024.pem 1024
$OPENSSL genrsa -out openssl.rsa2048.pem 2048

$OPENSSL rsa -outform PEM -in openssl.rsa1024.pem -pubout -out openssl.rsa1024.pub.pem
$OPENSSL rsa -outform PEM -in openssl.rsa2048.pem -pubout -out openssl.rsa2048.pub.pem

# Encrypted
$OPENSSL rsa -outform PEM -in openssl.rsa1024.pem -aes-128-cbc -passout pass:mypassword -out openssl.rsa1024.enc.pem
$OPENSSL rsa -outform PEM -in openssl.rsa2048.pem -aes-192-cbc -passout pass:mypassword -out openssl.rsa2048.enc.pem

#######################################
# RFC 5915                            #
#######################################

# P-266, P-384, P-521:
$OPENSSL ecparam -genkey -outform PEM -name prime256v1 -noout -out openssl.p256.pem
$OPENSSL ecparam -genkey -outform PEM -name secp384r1 -noout -out openssl.p384.pem
$OPENSSL ecparam -genkey -outform PEM -name secp521r1 -noout -out openssl.p521.pem

$OPENSSL ec -outform PEM -in openssl.p256.pem -pubout -out openssl.p256.pub.pem
$OPENSSL ec -outform PEM -in openssl.p384.pem -pubout -out openssl.p384.pub.pem
$OPENSSL ec -outform PEM -in openssl.p521.pem -pubout -out openssl.p521.pub.pem

$OPENSSL ec -outform PEM -in openssl.p256.pem -aes-256-cbc -passout pass:mypassword -out openssl.p256.enc.pem
$OPENSSL ec -outform PEM -in openssl.p384.pem -des -passout pass:mypassword -out openssl.p384.enc.pem
$OPENSSL ec -outform PEM -in openssl.p521.pem -des3 -passout pass:mypassword -out openssl.p521.enc.pem

#######################################
# OPENSSH                             #
#######################################

# EC
for size in 256 384 521
do
   $SSH_KEYGEN -t ecdsa -b $size -f openssh.p$size.pem -N ""
   mv openssh.p$size.pem.pub openssh.p$size.pub.pem
   cp openssh.p$size.pem openssh.p$size.enc.pem
   $SSH_KEYGEN -p -N mypassword -f openssh.p$size.enc.pem
done

# Ed25519
$SSH_KEYGEN -t ed25519 -f openssh.ed25519.pem -N ""
mv openssh.ed25519.pem.pub openssh.ed25519.pub.pem
cp openssh.ed25519.pem openssh.ed25519.enc.pem
$SSH_KEYGEN -p -N mypassword -f openssh.ed25519.enc.pem

# RSA
for size in 1024 2048
do
   $SSH_KEYGEN -t rsa -b $size -f openssh.rsa$size.pem -N ""
   mv openssh.rsa$size.pem.pub openssh.rsa$size.pub.pem
   cp openssh.rsa$size.pem openssh.rsa$size.enc.pem
   $SSH_KEYGEN -p -N mypassword -f openssh.rsa$size.enc.pem
done
