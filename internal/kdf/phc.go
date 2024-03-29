package kdf

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// phcEncoding is the alphabet used to encode/decode the hashes. It's based on
// the PHC string format:
//
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
var phcEncoding = base64.RawStdEncoding

// phcAtoi returns the number in the string value or n if value is empty.
func phcAtoi(value string, n int) (int, error) {
	if value == "" {
		return n, nil
	}
	return strconv.Atoi(value)
}

// phcParamsToMap parses the parameters in the string s and returns them in a
// map of keys and values.
func phcParamsToMap(s string) map[string]string {
	parameters := strings.Split(s, ",")
	m := make(map[string]string, len(parameters))
	for _, p := range parameters {
		subs := strings.SplitN(p, "=", 2)
		if len(subs) == 2 {
			m[subs[0]] = subs[1]
		} else {
			m[subs[0]] = ""
		}
	}
	return m
}

// phcEncode creates a string using the PHC format.
func phcEncode(identifier, params string, salt, hash []byte) string {
	ret := "$" + identifier
	if params != "" {
		ret += "$" + params
	}
	if len(salt) > 0 {
		ret += "$" + phcEncoding.EncodeToString(salt)
	}
	if len(hash) > 0 {
		ret += "$" + phcEncoding.EncodeToString(hash)
	}
	return ret
}

// phcDecode returns the different parts of a PHC encoded string.
func phcDecode(s string) (id string, version int, params string, salt, hash []byte, err error) {
	subs := strings.SplitN(s, "$", 6)
	if subs[0] != "" || len(subs) < 2 || (subs[1] == bcryptHash && len(subs) != 4) {
		return "", 0, "", nil, nil, errors.New("cannot decode password hash")
	}

	// Special case for bcrypt
	// return just the id and the full hash
	if subs[1] == bcryptHash {
		return bcryptHash, 0, "", nil, []byte(s), nil
	}

	switch len(subs) {
	case 6: // id + version + params + salt + hash
		// version: v=<dec>
		m := phcParamsToMap(subs[2])
		if version, err = phcAtoi(m["v"], 0); err != nil {
			return "", 0, "", nil, nil, err
		}
		if hash, err = phcEncoding.DecodeString(subs[5]); err != nil {
			return "", 0, "", nil, nil, err
		}
		if salt, err = phcEncoding.DecodeString(subs[4]); err != nil {
			return "", 0, "", nil, nil, err
		}
		id, params = subs[1], subs[3]
	case 5: // id + params + salt + hash
		if hash, err = phcEncoding.DecodeString(subs[4]); err != nil {
			return "", 0, "", nil, nil, err
		}
		if salt, err = phcEncoding.DecodeString(subs[3]); err != nil {
			return "", 0, "", nil, nil, err
		}
		id, params = subs[1], subs[2]
	case 4: // id + salt + hash
		if hash, err = phcEncoding.DecodeString(subs[3]); err != nil {
			return "", 0, "", nil, nil, err
		}
		if salt, err = phcEncoding.DecodeString(subs[2]); err != nil {
			return "", 0, "", nil, nil, err
		}
		id = subs[1]
	case 3: // id + params
		id, params = subs[1], subs[2]
	case 2: // id
		id = subs[1]
	default:
		return "", 0, "", nil, nil, errors.New("cannot decode password hash")
	}

	return
}
