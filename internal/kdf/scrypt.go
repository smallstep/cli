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

var (
	// ScryptMaxCost the maximum value for ln. Maximum is set to avoid
	// panics due to not enough memory errors. Memory used is ~4*32*(2^ln)*r
	// bytes.
	ScryptMaxCost = 20
	// ScryptMaxBlockSize is the maximum value for r. The maximum is set to
	// avoid panics due to not enough memory errors. Memory used is
	// ~4*32*(2^ln)*r bytes.
	ScryptMaxBlockSize = 32
	// ScryptMaxParallelism is the maximum value for p.
	ScryptMaxParallelism = 32
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
	params := phcParamsToMap(s)
	ln, err := phcAtoi(params["ln"], 16)
	if err != nil || ln < 1 || ln > ScryptMaxCost {
		return nil, errors.Errorf("invalid scrypt parameter ln=%s", params["ln"])
	}
	r, err := phcAtoi(params["r"], 8)
	if err != nil || r < 1 || r > ScryptMaxBlockSize {
		return nil, errors.Errorf("invalid scrypt parameter r=%s", params["r"])
	}
	p, err := phcAtoi(params["p"], 1)
	if err != nil || p < 1 || p > ScryptMaxParallelism {
		return nil, errors.Errorf("invalid scrypt parameter p=%s", params["p"])
	}

	return &scryptParam{
		N: int(math.Pow(2, float64(ln))),
		r: r,
		p: p,
	}, nil
}

func (s *scryptParam) getParams() string {
	return fmt.Sprintf("ln=%d,r=%d,p=%d", int(math.Log2(float64(s.N))), s.r, s.p)
}
