package kdf

import (
	"fmt"
	"math"

	"github.com/pkg/errors"
)

const (
	bcryptHash      = "2a"
	scryptHash      = "scrypt"
	scryptHash16384 = "scrypt-16384"
	scryptHash32768 = "scrypt-32768"
	scryptHash65536 = "scrypt-65536"
)

var scryptParams = map[string]scryptParam{
	scryptHash16384: {16384, 8, 1, 32},
	scryptHash32768: {32768, 8, 1, 32},
	scryptHash65536: {65536, 8, 1, 32},
}

type scryptParam struct {
	N, r, p int
	kl      int
}

func newScryptParams(s string) (*scryptParam, error) {
	sp := new(scryptParam)
	params := phcParamsToMap(s)

	if ln, err := phcAtoi(params["ln"], 16); err != nil {
		return nil, err
	} else if ln < 1 {
		return nil, errors.Errorf("invalid scrypt parameter ln=%s", params["ln"])
	} else {
		sp.N = int(math.Pow(2, float64(ln)))
	}

	if r, err := phcAtoi(params["r"], 8); err != nil {
		return nil, err
	} else if r < 1 {
		return nil, errors.Errorf("invalid scrypt parameter r=%s", params["r"])
	} else {
		sp.r = r
	}

	if p, err := phcAtoi(params["p"], 1); err != nil {
		return nil, err
	} else if p < 1 {
		return nil, errors.Errorf("invalid scrypt parameter p=%s", params["p"])
	} else {
		sp.p = p
	}

	return sp, nil
}

func (s *scryptParam) getParams() string {
	return fmt.Sprintf("ln=%d,r=%d,p=%d", int(math.Log2(float64(s.N))), s.r, s.p)
}
