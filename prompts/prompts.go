package prompts

import (
	"fmt"
	"io/ioutil"
	"strings"
	"unicode"

	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils/reader"
)

// Password prompts the user for a password if the provided pwdFilePath is
// empty, otherwise, it reads the password value from the given file path.
//
// If generate is true then a password will be generated for the user if the
// field is left empty.
func Password(prompt, name, pwdFilePath string, generate bool) (string, error) {
	var value string
	var err error
	if pwdFilePath != "" {
		value, err = readPasswordFile(pwdFilePath)
		if err != nil {
			return value, errs.Wrap(err, "Could not read password file '%s'", pwdFilePath)
		}

		return value, nil
	}

	valid := reader.RetryOnEmpty
	if generate {
		prompt = fmt.Sprintf("%s [leave blank to generate one automatically]: ", prompt)
		valid = reader.GeneratePasswordOnEmpty
	} else {
		prompt = fmt.Sprintf("%s: ", prompt)
	}

	err = reader.ReadPasswordSubtle(prompt, &value, name, valid)
	if err != nil {
		return "", err
	}

	return value, nil
}

func readPasswordFile(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return stripWhitespace(string(b[:])), nil
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}

		return r
	}, s)
}
