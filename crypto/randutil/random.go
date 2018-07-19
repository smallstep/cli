package randutil

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/pkg/errors"
)

// GetRandomSalt generates a new salt of the given size.
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, errors.Wrap(err, "error generating salt")
	}
	return salt, nil
}

// RandString returns a random string of a given length using the characters
// in the given string. It splits the string on runes to support UTF-8
// characters.
func RandString(length int, chars string) (string, error) {
	result := make([]rune, length)
	runes := []rune(chars)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(runes))))
		if err != nil {
			return "", errors.Wrap(err, "error creating random number")
		}
		result[i] = runes[num.Int64()]
	}
	return string(result), nil
}

// RandHex returns a random string of the given length using the hexadecimal
// characters in lower case (0-9+a-f).
func RandHex(length int) (string, error) {
	return RandString(length, "0123456789abcdef")
}

// RandAlphanumeric returns a random string of the given length using the 62
// alphanumeric characters in the POSIX/C locale (a-z+A-Z+0-9).
func RandAlphanumeric(length int) (string, error) {
	return RandString(length, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// GenerateRandomASCIIString returns a securely generated random ASCII string.
// It reads random numbers from crypto/rand and searches for printable characters.
// It will return an error if the system's secure random number generator fails to
// function correctly, in which case the caller must not continue.
func GenerateRandomASCIIString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			return result, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			result += string(n)
		}
	}
}

// GenerateRandomRestrictedString returns a securely generated random ASCII string.
// It reads random numbers from crypto/rand and searches for printable characters.
// It will return an error if the system's secure random number generator fails to
// function correctly, in which case the caller must not continue.
func GenerateRandomRestrictedString(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[num.Int64()]
	}
	return string(result), nil
}
