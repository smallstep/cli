package fingerprint

import (
	"crypto"
	_ "crypto/sha256"
	"os"
	"testing"
)

func TestEncodedFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		fn      string
		want    string
		options []Option
	}{
		{"default", "testdata/raw", "7261772d646174610a",
			[]Option{},
		},
		{"prefix", "testdata/raw", "PREFIX:7261772d646174610a",
			[]Option{WithPrefix("PREFIX:")},
		},
		{"sha256", "testdata/raw", "9d9b7b1f190165f8adaf15596b8d0ffd093f98dd022af12f0d214c3b55a6ed09",
			[]Option{WithHash(crypto.SHA256)},
		},

		{"hex", "testdata/ca.der", "6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98",
			[]Option{WithHash(crypto.SHA256), WithEncoding(HexFingerprint)},
		},
		{"base64", "testdata/ca.der", "aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat/pg=",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64Fingerprint)},
		},
		{"base64url", "testdata/ca.der", "aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat_pg=",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64URLFingerprint)},
		},
		{"base64raw", "testdata/ca.der", "aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat/pg",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64RawFingerprint)},
		},
		{"emoji", "testdata/ca.der", "🚁🍎👺🚌🏮☁️🎍👀🇮🇹✋🍼🚽⛅🐼🚬🎅🇷🇺🇷🇺🚂🤢🎀💩🚁🎆👺🎨👌✔️🚸🌈⚡🐼",
			[]Option{WithHash(crypto.SHA256), WithEncoding(EmojiFingerprint)},
		},

		{"prefix, hex", "testdata/ca.der", "PREFIX:6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98",
			[]Option{WithHash(crypto.SHA256), WithEncoding(HexFingerprint), WithPrefix("PREFIX:")},
		},
		{"prefix, base64", "testdata/ca.der", "PREFIX:aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat/pg=",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64Fingerprint), WithPrefix("PREFIX:")},
		},
		{"prefix, base64url", "testdata/ca.der", "PREFIX:aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat_pg=",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64URLFingerprint), WithPrefix("PREFIX:")},
		},
		{"prefix, base64raw", "testdata/ca.der", "PREFIX:aQh1H2gpDUVzrgvjmpjIube31OiypmlLdQmUZiat/pg",
			[]Option{WithHash(crypto.SHA256), WithEncoding(Base64RawFingerprint), WithPrefix("PREFIX:")},
		},
		{"prefix, emoji", "testdata/ca.der", "PREFIX:🚁🍎👺🚌🏮☁️🎍👀🇮🇹✋🍼🚽⛅🐼🚬🎅🇷🇺🇷🇺🚂🤢🎀💩🚁🎆👺🎨👌✔️🚸🌈⚡🐼",
			[]Option{WithHash(crypto.SHA256), WithEncoding(EmojiFingerprint), WithPrefix("PREFIX:")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := os.ReadFile(tt.fn)
			if err != nil {
				t.Fatalf("failed to read %s: %v", tt.fn, err)
			}

			if got := Fingerprint(input, tt.options...); got != tt.want {
				t.Errorf("EncodedFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}
