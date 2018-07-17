package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

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
