package jwe

import "github.com/urfave/cli"

// Command returns the jwe subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "jwe",
		Usage:     "encrypt and decrypt data and keys using JSON Web Encryption (JWE)",
		UsageText: "step crypto jwe <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `The **step crypto jwe** command group provides facilities for encrypting and
decrypting content and representing encrypted content using JSON-based data
structures as defined by the JSON Web Encryption (JWE) specification in
RFC7516, using algorithms defined in the JSON Web Algorithms (JWA)
specification in RFC7518. A JWE is a data structure representing an encrypted
and integrity-protected message.

There are two JWE serializations: the compact serialization is a small, URL-
safe representation that base64 encodes the JWE components. The compact
serialization is a URL-safe string, suitable for space-constrained
environments such as HTTP headers and URI query parameters. The JSON
serialization represents JWEs as JSON objects and allows the same content to
be encrypted to multiple parties (using multiple keys).

A typical JWE in compact serialization is a dot-separated string with five
parts:

* Header: metadata describing how the plaintext payload was processed to
  produce ciphertext (e.g., which algorithms were used to encrypt the
  content encryption key and the plaintext payload)

* Encrypted Key: the "content encryption key" that was used to encrypt the
  plaintext payload, encrypted for the JWE recipient(s) (see: "what's with
  the encrypted key" below)

* Initialization Vector: an initialization vector for use with the specified
  encryption algorithm, if applicable

* Ciphertext: the ciphertext value resulting produced from authenticated
  encryption of the plaintext with additional authenticated data

* Authentication Tag: value resulting from the authenticated encryption of
  the plaintext with additional authenticated data

## What's with encrypted key?

This is somewhat confusing. Instead of directly encrypting the plaintext
payload, JWE typically generates a new "content encryption key" then encrypts
*that key* for the intended recipient(s).

While versatile, JWE is easy to use incorrectly. Therefore, any use of this
subcommand requires the use of the '--subtle' flag as a misuse prevention
mechanism. You should only use this subcommand if you know what you're doing.
If possible, you're better off using the higher level 'crypto nacl' command
group.

## EXAMPLES

This example demonstrates how to produce a JWE for a recipient using the
RSA-OAEP algorithm to encrypt the content encryption key (producing the
encrypted key), and the A256GCM (AES GCM with 256-bit key) algorithm to
produce the ciphertext and authentication tag.

1. Encode the JWE header with the desired "alg" and "enc" members then
   encode it producing the *header*
   '''raw
   BASE64URL(UTF8({"alg":"RSA-OAEP","enc":"A256GCM"}))
   => eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
   '''

2. Generate a random content encryption key (CEK), encrypt it using
   RSA-OAEP, producing the *encrypted key*

3. Generate a random initialization vector

4. Perform authenticated encryption over the plaintext using the content
   encryption key and A256GCM algorithm with the base64-encoded JWE headers
   provided as additional authenticated data producing the *ciphertext* and
   *authentication tag*

5. Assemble the final result (compact serialization) to produce the string:
   '''raw
   BASE64URL(UTF8(header)) || '.'
   || BASE64URL(encrypted key) || '.'
   || BASE64URL(initialization vector) || '.'
   || BASE64URL(ciphertext) || '.'
   || BASE64URL(authentication tag)
   '''
   Producing a result like (line breaks for display purposes only):
   '''raw
   eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
   OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
   ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
   Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
   mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
   1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
   6UklfCpIMfIjf7iGdXKHzg.
   48V1_ALb6US04U3b.
   5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
   SdiwkIr3ajwQzaBtQD_A.
   XFBoMYUZodetZdvTiFvSkQ
   '''

Create a JWK for encryption use:
'''
$ step crypto jwk create --use enc p256.enc.pub p256.enc.priv
'''

Encrypt a message using the previous public key (output indented for display purposes):
'''
$ echo The message | step crypto jwe encrypt --key p256.enc.pub
{
  "protected":"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii1hakZFVlZaSWNRa0RxbkhpZ0NOWU5fa29nZkhxZnRGX1N3c2ZQeXlSRUUiLCJ5IjoicGpjVnJJZHRHSVpka05HS1FETEpIdG5SLUxudUI2V3k4bHpuX3REdm9BUSJ9LCJraWQiOiJHd0tSTUdXY1pWNFE2dGZZblpjZm90N090N2hjQ0t2cUJPVWljX0JoZ0gwIn0",
  "iv":"-10PlAIteHLVABtt",
  "ciphertext":"_xnGoE7vPCrXRRlK",
  "tag":"wcvj4sXXMc9qII_ySYNYGA"
}
'''

Decrypt the previous message using the private key:
'''
$ step crypto jwe decrypt --key p256.enc.priv \< message.json
Please enter the password to decrypt p256.enc.priv: ********
The message
'''

Encrypt a message using a shared password:
'''
$ echo The message | step crypto jwe encrypt --alg PBES2-HS256+A128KW
Please enter the password to encrypt the content encryption key: ********
{
  "protected":"eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoxMDAwMDAsInAycyI6ImpKMnJpejJGZnhoSXVOS3JSYUJqc2cifQ",
  "encrypted_key":"p4xazaWvaAYC7NbHoAQTC4DxCX-rEjs7wvRF-OvaVliYzhdRtEdgzA",
  "iv":"Jw4JCCr-lLrE0irT",
  "ciphertext":"jcb3wKopsHmClh7s",
  "tag":"7ttDDDfuqA45puDu7KbVkA"
}
'''

Decrypt a message protected with shared password:
'''
$ step crypto jwe decrypt \< message.json
Please enter the password to decrypt the content encryption key: ********
The message
'''`,
		Subcommands: cli.Commands{
			encryptCommand(),
			decryptCommand(),
		},
	}
}
