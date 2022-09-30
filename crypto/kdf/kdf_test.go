package kdf

import (
	"testing"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/randutil"
)

func TestKDF(t *testing.T) {
	tests := []struct {
		kdf    KDF
		prefix string
	}{
		{Scrypt, "$scrypt$ln=15,r=8,p=1$"},
		{Bcrypt, "$2a$10$"},
		{Argon2i, "$argon2i$v=19$m=32768,t=3,p=4$"},
		{Argon2id, "$argon2id$v=19$m=65536,t=1,p=4$"},
	}

	for _, tc := range tests {
		for _, l := range []int{0, 1, 8, 16, 32} {
			// With random bytes
			bytes, err := randutil.Salt(l)
			assert.FatalError(t, err)

			phc, err := tc.kdf(bytes)
			assert.HasPrefix(t, phc, tc.prefix)
			assert.FatalError(t, err)

			ok, err := Compare(bytes, []byte(phc))
			assert.True(t, ok)
			assert.NoError(t, err)

			// With strings
			str, err := randutil.ASCII(l)
			assert.FatalError(t, err)

			phc, err = tc.kdf([]byte(str))
			assert.HasPrefix(t, phc, tc.prefix)
			assert.FatalError(t, err)

			ok, err = CompareString(str, phc)
			assert.True(t, ok)
			assert.NoError(t, err)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		phc string
		err string
	}{
		// No errors
		{"$scrypt$ln=15,r=8,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", ""},
		{"$2a$10$73EPXSX148BO6fNUh6OEJee2.BbL2A.UhEPmI3.adgzacMULpIoum", ""},
		{"$argon2i$v=19$m=32768,t=3,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", ""},
		{"$argon2id$v=19$m=65536,t=1,p=4$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", ""},
		// invalid hash
		{"", "error decoding hash: cannot decode password hash"},
		{"foo", "error decoding hash: cannot decode password hash"},
		{"$bar$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", "invalid or unsupported hash method with id 'bar'"},
		// params
		{"$scrypt$ln=0,r=8,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter ln=0"},
		{"$scrypt$ln=15,r=0,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter r=0"},
		{"$scrypt$ln=15,r=8,p=0$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter p=0"},
		{"$scrypt$ln=21,r=8,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter ln=21"},
		{"$scrypt$ln=16,r=33,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter r=33"},
		{"$scrypt$ln=16,r=8,p=33$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter p=33"},
		{"$scrypt$ln=a,r=8,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter ln=a"},
		{"$scrypt$ln=16,r=b,p=1$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter r=b"},
		{"$scrypt$ln=16,r=8,p=c$3ZHBQhuxmarEmhzCdQ0JRQ$FzNGtwDLay5mHJIfc+L8qzOQrOG8RhR865Dr8GfyEK4", "invalid scrypt parameter p=c"},
		// version
		{"$argon2i$v=10$m=32768,t=3,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "unsupported argon2 version '10'"},
		{"$argon2id$v=10$m=65536,t=1,p=4$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", "unsupported argon2 version '10'"},
		// params
		{"$argon2i$v=19$m=0,t=3,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter m=0"},
		{"$argon2id$v=19$m=32768,t=0,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter t=0"},
		{"$argon2i$v=19$m=32768,t=3,p=0$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter p=0"},
		{"$argon2id$v=19$m=16777217,t=3,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter m=16777217"},
		{"$argon2id$v=19$m=65536,t=129,p=1$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter t=129"},
		{"$argon2id$v=19$m=65536,t=1,p=33$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter p=33"},
		{"$argon2i$v=19$m=a,t=3,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter m=a"},
		{"$argon2i$v=19$m=32768,t=b,p=4$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter t=b"},
		{"$argon2i$v=19$m=32768,t=3,p=c$kAaLk++2eObkl3QhDhabKA$IiL7+VDQV/YbDQMREkAhsWjX7GQy1ks0QiJ0YfkeA+w", "invalid argon2 parameter p=c"},
		{"$argon2id$v=19$m=a,t=1,p=4$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", "invalid argon2 parameter m=a"},
		{"$argon2id$v=19$m=65536,t=b,p=4$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", "invalid argon2 parameter t=b"},
		{"$argon2id$v=19$m=65536,t=1,p=c$mm6faLHx88uYB5m+04udUg$9deA/VOr2HEOb5JSZ0E6t+SVzV1iPpOuyr+jUhcPAWY", "invalid argon2 parameter p=c"},
	}

	for i, tc := range tests {
		ok, err := CompareString("password", tc.phc)
		assert.False(t, ok, tc.phc)
		if tc.err == "" {
			assert.NoError(t, err, i, err)
		} else if assert.Error(t, err) {
			assert.Equals(t, tc.err, err.Error(), i, tc.err, err.Error())
		}
	}
}

func TestVectors(t *testing.T) {
	tests := []struct {
		password string
		phc      string
	}{
		{"", "$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEL80Aad7QlI+DJqdToPyB8X6NPg+y4NNijPNeIMONGJBg"},
		{"password", "$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA"},
		{"pleaseletmein", "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw"},
		{"pleaseletmein", "$scrypt$ln=20,r=8,p=1$U29kaXVtQ2hsb3JpZGU$IQHLm2pRGq6t274Jz3D4gexWjVdKL/1Nq+XumCCtqkeOVv2PS6XQn/ocbZJ8QPTDNzBASeipUvvL9Fxvp3pBpA"},
		{"password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"},
		{"password", "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E"},
		{"gCb0SBnpxkdLZdWe", "$argon2i$v=19$m=131072,t=4,p=1$a1NtbUJTeTV1eUM0$gNxxt8jHCHaKDUcbdP3ugX9i+BA"},
		{"9wQdHVSks3tbXx", "$argon2i$v=19$m=65536,t=5,p=1$SFc0QWdJblFvVQ$IwHIJ6VP1vIV7xrKm+mlI1nupA"},
		{"nPeXb5WW", "$argon2i$v=19$m=16384,t=5,p=1$RGliSnd2SldhcnlTSUlpYw$3n/DLofidmz8LPnM925hbm+4He/iKjAlvG4"},
		{"password", "$argon2id$v=19$m=4096,t=3,p=1$PcEZHj1maR/+ZQynyJHWZg$2jEN4xcww7CYp1jakZB1rxbYsZ55XH2HgjYRtdZtubI"},
		{"s3kr3tp4ssw0rd", "$argon2id$v=19$m=512,t=2,p=2$Z0tsPw0iK7Ky2Iwp63HKBA$psMUXgYOIaAhaZ990uep8w"},
		{"s3kr3tp4ssw0rd", "$argon2id$v=19$m=512,t=2,p=2$Wd3CJItnL93pSLG/Mvel2g$DnsqcrS7+Enwu8EdJrUX2Q"},
		{"6GaBkxnU", "$argon2id$v=19$m=131072,t=1,p=1$U0lXQXVWa2xMVQ$+EaGmstgtSas9elKIXLVqcybaYJIBWifLeLWkFAZ"},
		{"JU1K5W8rzP1K", "$argon2id$v=19$m=65536,t=3,p=1$OUp2ZTFYNU9RMnRw$7yApdAtgdaPQZWisUa58lb328fR+kgznHqQqcafaCg"},
		{"oxx700QV8RVHQA2l", "$argon2id$v=19$m=131072,t=5,p=1$cjhSN05xc055Yg$yHz0aPvCukbkMw1oXaKejEkG6Q"},
		{"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
		{"", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
		{"", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
		{"", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
		{"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
		{"a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
		{"a", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
		{"a", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
		{"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
		{"abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
		{"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
		{"abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
		{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
		{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
		{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
		{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"},
	}

	for _, tc := range tests {
		ok, err := CompareString(tc.password, tc.phc)
		assert.True(t, ok, tc.phc)
		assert.NoError(t, err)
	}
}
