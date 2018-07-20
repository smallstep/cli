package randutil

import (
	"crypto/rand"
	"errors"
	"regexp"
	"testing"

	"github.com/smallstep/assert"
)

func TestErrors(t *testing.T) {
	// with errors
	df := forceErrorRandReader()
	defer df()

	sizes := []int{4, 8, 16, 32}
	for _, size := range sizes {
		b, err := Salt(size)
		assert.Error(t, err)
		assert.Len(t, 0, b)

		str, err := String(size, "0123456789")
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = Hex(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = Alphanumeric(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = ASCII(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)
	}
}

func TestSalt(t *testing.T) {
	sizes := []int{4, 8, 16, 32}
	for _, size := range sizes {
		a, err := Salt(size)
		assert.NoError(t, err)
		b, err := Salt(size)
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestString(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9世界ñçàèìòù]+$`)
	chars := "0123456789世界ñçàèìòù"
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := String(l, chars)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := String(l, chars)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestHex(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-f]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Hex(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Hex(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestAlphanumeric(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Alphanumeric(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Alphanumeric(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestASCII(t *testing.T) {
	re := regexp.MustCompilePOSIX("^[\x21-\x7E]+$")
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := ASCII(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := ASCII(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

type errorReader struct{}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("an error")
}

func forceErrorRandReader() func() {
	old := rand.Reader
	rand.Reader = new(errorReader)
	return func() {
		rand.Reader = old
	}
}
