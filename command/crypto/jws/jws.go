package jws

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "jws",
		Usage:     "sign and verify data using JSON Web Signature (JWS)",
		UsageText: "step crypto jws <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `JSON Web Signature (JWS) represents content secured with digital signatures or
Message Authentication Codes (MACs) using JSON-based data structures.

## EXAMPLES

Create a signed JWS of a message using an Ed25519 private JWK (with line
breaks for display purposes only):
'''
$ echo -n message | step crypto jws sign --key ed25519.priv.json
eyJhbGciOiJFZERTQSIsImtpZCI6IjlxaVFZUFU3SHJTOXBYdXpYYzc1WGctMXc5c0JGM2lXVld2cDhieE5oc28ifQ
.
bWVzc2FnZQ
.
ZlJvznC3iE4zhwmnCL74UtHXEUs6pb62vf38GFBLbFMKnIFiOGpAFcNv3es-WvPHYfyIIClAjwCfe505gxz5BQ
'''

Verify and display the message using the public key:
'''
$ echo $TOKEN | step crypto jws verify --key ed25519.pub.json
message
'''

Verify and display a JSON representation of the token, the message is base64
encoded in the payload:
'''
$ echo $TOKEN | step crypto jws verify --key ed25519.pub.json --json
{
  "header": {
    "alg": "EdDSA",
    "kid": "9qiQYPU7HrS9pXuzXc75Xg-1w9sBF3iWVWvp8bxNhso"
  },
  "payload": "bWVzc2FnZQ",
  "signature": "ZlJvznC3iE4zhwmnCL74UtHXEUs6pb62vf38GFBLbFMKnIFiOGpAFcNv3es-WvPHYfyIIClAjwCfe505gxz5BQ"
}
'''

Inspect the content of the JWS without verifying it:
'''
$ echo $TOKEN | step crypto jws inspect --insecure
message

$ echo $TOKEN | step crypto jws inspect --insecure --json
{
  "header": {
    "alg": "EdDSA",
    "kid": "9qiQYPU7HrS9pXuzXc75Xg-1w9sBF3iWVWvp8bxNhso"
  },
  "payload": "bWVzc2FnZQ",
  "signature": "ZlJvznC3iE4zhwmnCL74UtHXEUs6pb62vf38GFBLbFMKnIFiOGpAFcNv3es-WvPHYfyIIClAjwCfe505gxz5BQ"
}
'''

Using a JSON message using an P-256 curve and adding the content type json:
'''
$ echo -n {"dns":"https://dns.example.com"} | step crypto jws sign --key p256.priv.json --cty json
eyJhbGciOiJFUzI1NiIsImN0eSI6Impzb24iLCJraWQiOiJWOTNBLVloN0JodzFXMkUwaWdGY2l2aUp6WDRQWFBzd29WZ3JpZWhtOUNvIn0
.
eyJkbnMiOiJodHRwczovL2Rucy5leGFtcGxlLmNvbSJ9
.
ZI8q75r3PCXeu-Tubw7bHiDGxloPpAHV2hNfEp9N4WM2r3Wsk5uFhAkBTVIqryPtxmAgfRHGnE3hj-3Dp9nZmA

$ echo $TOKEN | step crypto jws verify --key p256.pub.json
{"dns":"https://dns.example.com"}

$ echo $TOKEN | step crypto jws verify --key p256.pub.json --json
{
  "header": {
    "alg": "ES256",
    "cty": "json",
    "kid": "V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co"
  },
  "payload": "eyJkbnMiOiJodHRwczovL2Rucy5leGFtcGxlLmNvbSJ9",
  "signature": "ZI8q75r3PCXeu-Tubw7bHiDGxloPpAHV2hNfEp9N4WM2r3Wsk5uFhAkBTVIqryPtxmAgfRHGnE3hj-3Dp9nZmA"
}
'''`,
		Subcommands: cli.Commands{
			signCommand(),
			inspectCommand(),
			verifyCommand(),
		},
	}
}
