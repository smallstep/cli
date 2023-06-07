package token

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

const (
	jwkToken  = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImpPMzdkdERia3UtUW5hYnM1VlIwWXc2WUZGdjl3ZUExOGRwM2h0dmRFanMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2NhLnNtYWxsc3RlcC5jb206OTAwMC8xLjAvc2lnbiIsImV4cCI6MTU1NTU0OTk1NywiaWF0IjoxNTU1NTQ5NjU3LCJpc3MiOiJtYXJpYW5vQHNtYWxsc3RlcC5jb20iLCJqdGkiOiJkNThmOWM0YmJhNmVjNTZhYTA1Yzc2N2I4MGE2NjQyMjBlYzZmZGJlYjVjYmVjYmU0OTI2MGRiNjc5NWRkODFlIiwibmJmIjoxNTU1NTQ5NjU3LCJzYW5zIjpbImZvby5iYXIuemFyIl0sInNoYSI6IjJkZDRmN2Q2NTNjNWE0ZjE4MjQ4YTkwM2M2ZTNkNjdiMTcwNDkyMzQxOWM5Zjc0NGZkNjgwZmM2NTI0MmYzYjIiLCJzdWIiOiJmb28uYmFyLnphciJ9.8GmY7dnjFQiXCABjD01n0-3hw4pNwMwdGBLxR4Qx1-pCr6PNlrZaN44QIsDfsi70hZFVdlG4l5MjGU8r4OopIg"
	jwkJWKSet = `{
	"keys": [
		{
			"use": "sig",
			"kty": "EC",
			"kid": "jO37dtDbku-Qnabs5VR0Yw6YFFv9weA18dp3htvdEjs",
			"crv": "P-256",
			"alg": "ES256",
			"x": "vo6GTwfXryV5WDI-_JL1FeK0k2AvWwUnSbtdSE3IQl0",
			"y": "Z4j_nNmETqTsKq-6ZCjyCIIMNE_308Mx866z3pD6sJ0"
		 }
	]
}`
	oidcToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM3ODJkM2YwYmM4OTAwOGQ5ZDJjMDE3MzBmNzY1Y2ZiMTlkM2I3MGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDg3MTYwNDg4NDIwLThxdDdiYXZnM3Flc2RoczZpdDgyNG1obmZnY2ZlOGlsLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA4NzE2MDQ4ODQyMC04cXQ3YmF2ZzNxZXNkaHM2aXQ4MjRtaG5mZ2NmZThpbC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNDQyMzU1MDUwMjY2NTkyMDEwMiIsImhkIjoic21hbGxzdGVwLmNvbSIsImVtYWlsIjoibWFyaWFub0BzbWFsbHN0ZXAuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJZVTJUQVN4LW42NjBqUWZOb0h2SHlnIiwibm9uY2UiOiI4ZWRhMDU2YjMyMjIwYWRjYjZhMjcxNjM1NzFkZjI1M2E3NjM5ZjM0YWQ2NDQ0MWIyNDI5YTNkZTJjNWQ3ZWFmIiwiaWF0IjoxNTU1NTUwNjY3LCJleHAiOjE1NTU1NTQyNjd9.LZ0OymOWMt59aqdsDr8TorxJ-J3ZpCjUjnA8m-TabcZmVgODqJpi8b5Z5O9Tnam3GHPjAAmPTGBEcF3VvH73RIF5p4nFJFL1sVtWetWR3kotWxha8mb5BKgW19NDDQSYKoQZXLZLmzBuaeBdjfZ8FGYrUaHHz4UdmlPjq38D_Oc7ZXNi7opMvjb8FKCQuT1rvJZzpOD8lA9lAnN82Z9IWLSJRUV39ecV0SiF1tPDimIjbvvfXNRUS7wgBVbUMSJW1YnXNGE8gtEd2OEFABaqrqqrf3RoWowav-wNAYVj56pQBwhnj7ALXciRXCAjxiL6kJQrhLLDnWup_ihohI9C0g"
	gcpToken  = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM3ODJkM2YwYmM4OTAwOGQ5ZDJjMDE3MzBmNzY1Y2ZiMTlkM2I3MGUiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJnY3A6S29wcyBQcm92aXNpb25lciIsImF6cCI6IjEwNjY1MjI1MDIxMTYwNjU0NjIyMyIsImVtYWlsIjoiODQ3MjUwNjI1OTAwLWNvbXB1dGVAZGV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNTU1NTQ3ODY4LCJnb29nbGUiOnsiY29tcHV0ZV9lbmdpbmUiOnsiaW5zdGFuY2VfY3JlYXRpb25fdGltZXN0YW1wIjoxNTU1NDQxMzQ2LCJpbnN0YW5jZV9pZCI6IjMwMTUzNzg2NjEwNDcwMDcyODYiLCJpbnN0YW5jZV9uYW1lIjoia29wcy1hZG1pbiIsInByb2plY3RfaWQiOiJrb3BzLWRldi0yMDE5LTAxIiwicHJvamVjdF9udW1iZXIiOjg0NzI1MDYyNTkwMCwiem9uZSI6InVzLWNlbnRyYWwxLWMifX0sImlhdCI6MTU1NTU0NDI2OCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTA2NjUyMjUwMjExNjA2NTQ2MjIzIn0.ozbrQ8aoDKbc5IYWUntGOiff9Yvl2vaceEDXe9X4uHUz_PANfLMgx-VGxGnEtr-QXT0BVTYxY0gVaAiO_FvuvyPf_6Zn-a3l7o2quZtO1zZziOX9QnwFoLRyT1kUZ3lq50h-oP5u79iAwDfk2PbKs1CgILDFs7EUbxJt1cXhW2KxJokk8Fy4nfPzx2Wg8RbYm_pgQv1wPnitLXBAbyLDyNIA03myrhgYkXxogp_AsT8VH_nCyP_b_autTN3W3_o_UIpxXZljr8fVjHrWjP-tz9gNuh1W1o_tekjcrmDiswJmokOme15L5gV8oMS-WZ1EZ01i3SoDkVMJcg3-jTXVEA"
	gcpJWKSet = `{
	"keys": [
	  {
		"kid": "6f6781ba71199a658e760aa5aa93e5fc3dc752b5",
		"e": "AQAB",
		"kty": "RSA",
		"alg": "RS256",
		"n": "1J287_drOWg9YJohe9TO7T0_l3EFkXOOWECkX5U-7ELhGFcfSnug-X7jnk4UJe2IyzlxZYSzsshUgTAvXSkLQCbkNT9gqigOmE7X70UAKaaq3IryR_yM92kpmBeH0zoNRFr-0f9vATrt3E2q9oKyKT16NEyzWqurk9w5cgdEB27OF389ftFK8H-BOtyB1gGziLvXVY4UTVfGOPe8VKTt2TfNWrdc40gt9L8iW4hCDzMlYCZQ-61dLhj_muIYXDXDfMqH1YK_JaCzAowzzuw6zCWLd9cUEAncotEbEsQUGqhof7KIsuX96ajGZKOWKBkvzBOUzr8EaOU4YGAyOvyVJw",
		"use": "sig"
	  },
	  {
		"e": "AQAB",
		"kty": "RSA",
		"alg": "RS256",
		"n": "vIs0vGoFJRWXRbPOwrbkAYtocuQbkHON9xUdC3Yp0Wyg1RXGnFjO4EZJWiWXlIRdMORW_ABEz8ggh5-51zdSZK4RES7OglD9TzoUvZgCwveI__wz2YvqvvZjelHixksHJn7dxBKd_qIB94A9JCtTTcX4tJExugBrZz5OpS9PoBeR4_cwHRk2618Q9CezhjBmOWEW5kyfDAhzJc8f6mpd1pX004e_OybD6xhfUHgnB0vT45ocFHmKzZ5LGfJyPxqXkLkpezofEC4lO5ru9yUhK209s7GABo39ZX6gYjHKocKeGxMRw2jZ_5jBK9-jcp9upqO7sgbfGpHjxZE6Pr6bsw",
		"use": "sig",
		"kid": "3782d3f0bc89008d9d2c01730f765cfb19d3b70e"
	  }
	]
}`
	awsToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbWF6b24iOnsiZG9jdW1lbnQiOiJld29nSUNKaFkyTnZkVzUwU1dRaU9pQWlTVzV0UWxOMGVuaDJjeUlzQ2lBZ0ltRnlZMmhwZEdWamRIVnlaU0k2SUNKNE9EWmZOalFpTEFvZ0lDSmhkbUZwYkdGaWFXeHBkSGxhYjI1bElqb2dJblZ6TFhkbGMzUXRNbUlpTEFvZ0lDSmlhV3hzYVc1blVISnZaSFZqZEhNaU9pQnVkV3hzTEFvZ0lDSmtaWFp3WVhsUWNtOWtkV04wUTI5a1pYTWlPaUJ1ZFd4c0xBb2dJQ0pwYldGblpVbGtJam9nSWxOQk5IaFpWVEZGWWtRaUxBb2dJQ0pwYm5OMFlXNWpaVWxrSWpvZ0lsb3pXRmRzV0VkT1dsSWlMQW9nSUNKcGJuTjBZVzVqWlZSNWNHVWlPaUFpZERJdWJXbGpjbThpTEFvZ0lDSnJaWEp1Wld4SlpDSTZJQ0lpTEFvZ0lDSndaVzVrYVc1blZHbHRaU0k2SUNJeU1ERTVMVEExTFRBNVZEQXhPakEwT2pJekxqVXlORFkyT1ZvaUxBb2dJQ0p3Y21sMllYUmxTWEFpT2lBaU1USTNMakF1TUM0eElpd0tJQ0FpY21GdFpHbHphMGxrSWpvZ0lpSXNDaUFnSW5KbFoybHZiaUk2SUNKMWN5MTNaWE4wTFRFaUxBb2dJQ0oyWlhKemFXOXVJam9nSWpJd01UY3RNRGt0TXpBaUNuMD0iLCJzaWduYXR1cmUiOiJKbkdlaWl2UzMrU1QxNGdFd2NCQS9MK0dHYkRyZm1iWmh3dU9tMjIrbFhqWjZzSUN4YUpRaFg1bmxyRDBrZUlvL2Y0dmRkT3FGTzhvUWNHd0J1YXl6aHFSVEt6cGpZVXBoSDFRMlJBUGl4dmcvZ0NSZG5YV0pETHpIRGhjTXdraCtvWnpFTkFuSTlhWGR4Vko4dGFKSlRHZ2lEVzdBcXYzK1JYZG4xcndiVVE9In0sImF1ZCI6WyJhd3M6TGdONHU4OUliNyJdLCJleHAiOjE1NTczNjQxNjMsImlhdCI6MTU1NzM2Mzg2MywiaXNzIjoiZWMyLmFtYXpvbmF3cy5jb20iLCJqdGkiOiI2ZDAyZDQ1MTEzODUzOTc3OTRmMmJkNjc0M2I1Nzc0MmIyNDMzYzE1Y2ZhNjEzZGNjYWYwNmNiMzUzOGY5YzJmIiwibmJmIjoxNTU3MzYzODYzLCJzYW5zIjpudWxsLCJzdWIiOiJaM1hXbFhHTlpSIn0.bP40Dk1YMQlNMK_XYVde93x53c92hCwYCsUp4tL7wrA"
	// azureToken represents a token obtained by a VM from the Azure IMDS (where the resource type is Microsoft.Compute/virtualMachines)
	azureToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjY2YjQxZjFlOTNmYTM5YTQzMjVkNmFhYmNlZGYwODJhZjg0NGZiMjJlZTk1NDAzYmVmOWQ0ZGNmMzcwYjcxMGUiLCJ0eXAiOiJKV1QifQ.eyJhcHBpZCI6InRoZS1hcHBpZCIsImFwcGlkYWNyIjoidGhlLWFwcGlkYWNyIiwiYXVkIjpbImh0dHBzOi8vbWFuYWdlbWVudC5henVyZS5jb20vIl0sImV4cCI6MTU1NzM0NTY1OCwiaWF0IjoxNTU3MzQ1MzU4LCJpZHAiOiJ0aGUtaWRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvUDg3aEFXVUUwYy8iLCJqdGkiOiJ0aGUtanRpIiwibmJmIjoxNTU3MzQ1MzU4LCJvaWQiOiJ0aGUtb2lkIiwic3ViIjoic3ViamVjdCIsInRpZCI6IlA4N2hBV1VFMGMiLCJ2ZXIiOiJ0aGUtdmVyc2lvbiIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL3N1YnNjcmlwdGlvbklEL3Jlc291cmNlR3JvdXBzL3Jlc291cmNlR3JvdXAvcHJvdmlkZXJzL01pY3Jvc29mdC5Db21wdXRlL3ZpcnR1YWxNYWNoaW5lcy92aXJ0dWFsTWFjaGluZSJ9.U_NdLMXLztkYEn0RXYD394SiR-QpaJ8eoRFBu0FYQJ6zDflc-veAceFbLsTdihNE21zm7qYAkDqXlE0q3Y7Zdg"
	// azureTokenMI represents a token obtained by a ManagedIdentity from the Azure IMDS
	// This type of token has a different resource id (specifically the resource type is Microsoft.ManagedIdentity/userAssignedIdentities)
	azureTokenMI = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjY2YjQxZjFlOTNmYTM5YTQzMjVkNmFhYmNlZGYwODJhZjg0NGZiMjJlZTk1NDAzYmVmOWQ0ZGNmMzcwYjcxMGUiLCJ0eXAiOiJKV1QifQ.eyJhcHBpZCI6InRoZS1hcHBpZCIsImFwcGlkYWNyIjoidGhlLWFwcGlkYWNyIiwiYXVkIjpbImh0dHBzOi8vbWFuYWdlbWVudC5henVyZS5jb20vIl0sImV4cCI6MTU1NzM0NTY1OCwiaWF0IjoxNTU3MzQ1MzU4LCJpZHAiOiJ0aGUtaWRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvUDg3aEFXVUUwYy8iLCJqdGkiOiJ0aGUtanRpIiwibmJmIjoxNTU3MzQ1MzU4LCJvaWQiOiJ0aGUtb2lkIiwic3ViIjoic3ViamVjdCIsInRpZCI6IlA4N2hBV1VFMGMiLCJ2ZXIiOiJ0aGUtdmVyc2lvbiIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL3N1YnNjcmlwdGlvbklEL3Jlc291cmNlR3JvdXBzL3Jlc291cmNlR3JvdXAvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9tYW5hZ2VkSWRlbnRpdHlOYW1lIn0K.U_NdLMXLztkYEn0RXYD394SiR-QpaJ8eoRFBu0FYQJ6zDflc-veAceFbLsTdihNE21zm7qYAkDqXlE0q3Y7Zdg"
	badToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyeyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

func TestParse(t *testing.T) {
	mustKeys := func(s string) interface{} {
		keys := new(jose.JSONWebKeySet)
		if err := json.Unmarshal([]byte(s), keys); err != nil {
			t.Fatal(err)
		}
		return keys
	}
	mustJoseClaims := func(tok string) jose.Claims {
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			t.Fatal(err)
		}
		var c jose.Claims
		if err := jwt.UnsafeClaimsWithoutVerification(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}

	type args struct {
		token string
		key   interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    Payload
		wantErr bool
	}{
		{"ok JWK", args{jwkToken, mustKeys(jwkJWKSet)}, Payload{
			Claims: mustJoseClaims(jwkToken),
			SHA:    "2dd4f7d653c5a4f18248a903c6e3d67b1704923419c9f744fd680fc65242f3b2",
			SANs:   []string{"foo.bar.zar"},
		}, false},
		{"ok OIDC", args{oidcToken, mustKeys(gcpJWKSet)}, Payload{
			Claims:          mustJoseClaims(oidcToken),
			AuthorizedParty: "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com",
			AtHash:          "YU2TASx-n660jQfNoHvHyg",
			Email:           "mariano@smallstep.com",
			EmailVerified:   true,
			Hd:              "smallstep.com",
			Nonce:           "8eda056b32220adcb6a27163571df253a7639f34ad64441b2429a3de2c5d7eaf",
		}, false},
		{"ok GCP", args{gcpToken, mustKeys(gcpJWKSet)}, Payload{
			Claims:          mustJoseClaims(gcpToken),
			AuthorizedParty: "106652250211606546223",
			Email:           "847250625900-compute@developer.gserviceaccount.com",
			EmailVerified:   true,
			Google: &GCPGooglePayload{
				ComputeEngine: GCPComputeEnginePayload{
					InstanceID:                "3015378661047007286",
					InstanceName:              "kops-admin",
					InstanceCreationTimestamp: jose.NewNumericDate(time.Unix(1555441346, 0)),
					ProjectID:                 "kops-dev-2019-01",
					ProjectNumber:             847250625900,
					Zone:                      "us-central1-c",
				},
			},
		}, false},
		{"fail bad token", args{"foobarzar", mustKeys(jwkJWKSet)}, Payload{}, true},
		{"fail bad claims", args{badToken, mustKeys(jwkJWKSet)}, Payload{}, true},
		{"fail bad keys", args{jwkToken, mustKeys(gcpJWKSet)}, Payload{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.token, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false {
				if !reflect.DeepEqual(got.Payload, tt.want) {
					t.Errorf("Parse() = %v, want %v", got.Payload, tt.want)
				}
			}
		})
	}
}

func TestParseInsecure(t *testing.T) {
	mustJoseClaims := func(tok string) jose.Claims {
		jwt, err := jose.ParseSigned(tok)
		if err != nil {
			t.Fatal(err)
		}
		var c jose.Claims
		if err := jwt.UnsafeClaimsWithoutVerification(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mustBase64 := func(s string) []byte {
		b64, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b64
	}

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    Payload
		wantErr bool
	}{
		{"ok JWK", args{jwkToken}, Payload{
			Claims: mustJoseClaims(jwkToken),
			SHA:    "2dd4f7d653c5a4f18248a903c6e3d67b1704923419c9f744fd680fc65242f3b2",
			SANs:   []string{"foo.bar.zar"},
		}, false},
		{"ok OIDC", args{oidcToken}, Payload{
			Claims:          mustJoseClaims(oidcToken),
			AuthorizedParty: "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com",
			AtHash:          "YU2TASx-n660jQfNoHvHyg",
			Email:           "mariano@smallstep.com",
			EmailVerified:   true,
			Hd:              "smallstep.com",
			Nonce:           "8eda056b32220adcb6a27163571df253a7639f34ad64441b2429a3de2c5d7eaf",
		}, false},
		{"ok GCP", args{gcpToken}, Payload{
			Claims:          mustJoseClaims(gcpToken),
			AuthorizedParty: "106652250211606546223",
			Email:           "847250625900-compute@developer.gserviceaccount.com",
			EmailVerified:   true,
			Google: &GCPGooglePayload{
				ComputeEngine: GCPComputeEnginePayload{
					InstanceID:                "3015378661047007286",
					InstanceName:              "kops-admin",
					InstanceCreationTimestamp: jose.NewNumericDate(time.Unix(1555441346, 0)),
					ProjectID:                 "kops-dev-2019-01",
					ProjectNumber:             847250625900,
					Zone:                      "us-central1-c",
				},
			},
		}, false},
		{"ok AWS", args{awsToken}, Payload{
			Claims: mustJoseClaims(awsToken),
			Amazon: &AWSAmazonPayload{
				Document: []byte(`{
  "accountId": "InmBStzxvs",
  "architecture": "x86_64",
  "availabilityZone": "us-west-2b",
  "billingProducts": null,
  "devpayProductCodes": null,
  "imageId": "SA4xYU1EbD",
  "instanceId": "Z3XWlXGNZR",
  "instanceType": "t2.micro",
  "kernelId": "",
  "pendingTime": "2019-05-09T01:04:23.524669Z",
  "privateIp": "127.0.0.1",
  "ramdiskId": "",
  "region": "us-west-1",
  "version": "2017-09-30"
}`),
				Signature: mustBase64("JnGeiivS3+ST14gEwcBA/L+GGbDrfmbZhwuOm22+lXjZ6sICxaJQhX5nlrD0keIo/f4vddOqFO8oQcGwBuayzhqRTKzpjYUphH1Q2RAPixvg/gCRdnXWJDLzHDhcMwkh+oZzENAnI9aXdxVJ8taJJTGgiDW7Aqv3+RXdn1rwbUQ="),
				InstanceIdentityDocument: &AWSInstanceIdentityDocument{
					AccountID:        "InmBStzxvs",
					Architecture:     "x86_64",
					AvailabilityZone: "us-west-2b",
					ImageID:          "SA4xYU1EbD",
					InstanceID:       "Z3XWlXGNZR",
					InstanceType:     "t2.micro",
					KernelID:         "",
					PendingTime:      time.Unix(1557363863, 524669000).UTC(),
					PrivateIP:        "127.0.0.1",
					RamdiskID:        "",
					Region:           "us-west-1",
					Version:          "2017-09-30",
				},
			},
		}, false},
		{"ok Azure", args{azureToken}, Payload{
			Claims:           mustJoseClaims(azureToken),
			AppID:            "the-appid",
			AppIDAcr:         "the-appidacr",
			IdentityProvider: "the-idp",
			ObjectID:         "the-oid",
			TenantID:         "P87hAWUE0c",
			Version:          "the-version",
			XMSMirID:         "/subscriptions/subscriptionID/resourceGroups/resourceGroup/providers/Microsoft.Compute/virtualMachines/virtualMachine",
			Azure: &AzurePayload{
				SubscriptionID: "subscriptionID",
				ResourceGroup:  "resourceGroup",
				ResourceType:   "virtualMachines",
				ResourceName:   "virtualMachine",
			},
		}, false},
		{"ok Azure", args{azureTokenMI}, Payload{
			Claims:           mustJoseClaims(azureToken),
			AppID:            "the-appid",
			AppIDAcr:         "the-appidacr",
			IdentityProvider: "the-idp",
			ObjectID:         "the-oid",
			TenantID:         "P87hAWUE0c",
			Version:          "the-version",
			XMSMirID:         "/subscriptions/subscriptionID/resourceGroups/resourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/managedIdentityName",
			Azure: &AzurePayload{
				SubscriptionID: "subscriptionID",
				ResourceGroup:  "resourceGroup",
				ResourceType:   "userAssignedIdentities",
				ResourceName:   "managedIdentityName",
			},
		}, false},
		{"fail bad token", args{"foobarzar"}, Payload{}, true},
		{"fail bad claims", args{badToken}, Payload{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInsecure(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false {
				if !reflect.DeepEqual(got.Payload, tt.want) {
					t.Errorf("Parse() = %v, want %v", got.Payload, tt.want)
				}
			}
		})
	}
}

func TestPayload_Type(t *testing.T) {
	type fields struct {
		SHA    string
		SANs   []string
		Google *GCPGooglePayload
		Amazon *AWSAmazonPayload
		Azure  *AzurePayload
		Claims *jose.Claims
	}
	tests := []struct {
		name   string
		fields fields
		want   Type
	}{
		{"JWK", fields{"a-sha", []string{"foo.bar.zar"}, nil, nil, nil, nil}, JWK},
		{"JWK no sans", fields{"a-sha", nil, nil, nil, nil, nil}, JWK},
		{"JWK no sha", fields{"", []string{"foo.bar.zar"}, nil, nil, nil, nil}, JWK},
		{"GCP", fields{"", nil, &GCPGooglePayload{}, nil, nil, nil}, GCP},
		{"AWS", fields{"", nil, nil, &AWSAmazonPayload{}, nil, nil}, AWS},
		{"Azure", fields{"", nil, nil, nil, &AzurePayload{}, nil}, Azure},
		{"Unknown", fields{"", nil, nil, nil, nil, nil}, Unknown},
		{"OIDC Kubernetes", fields{"", nil, nil, nil, nil, &jose.Claims{Audience: jose.Audience{"step-ca"}, Issuer: "https://kubernetes.default.svc.cluster.local", Subject: "system:serviceaccount:default:default", Expiry: jose.NewNumericDate(time.Now()), IssuedAt: jose.NewNumericDate(time.Now())}}, OIDC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Payload{
				SHA:    tt.fields.SHA,
				SANs:   tt.fields.SANs,
				Google: tt.fields.Google,
				Amazon: tt.fields.Amazon,
				Azure:  tt.fields.Azure,
			}
			if tt.fields.Claims != nil {
				p.Claims = *tt.fields.Claims
			}
			if got := p.Type(); got != tt.want {
				t.Errorf("Payload.Type() = %v, want %v", got, tt.want)
			}
		})
	}
}
