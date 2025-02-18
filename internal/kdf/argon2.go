package kdf

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/internal/cast"
)

const (
	argon2iHash  = "argon2i"
	argon2idHash = "argon2id"
)

var (
	// Argon2MaxMemory indicates the maximum amount of memory that Argon2 KDFs
	// can support. It defines the maximum value for the parameter m.  The
	// current value is set to 16GB.
	Argon2MaxMemory = 16 * 1048576

	// Argon2MaxParallelism is the maximum number of threads used. It's the
	// maximum value for the parameter p.
	Argon2MaxParallelism = 32

	// Argon2MaxIterations is the maximum number of iterations to run. It's the
	// maximum value for the parameter t.
	Argon2MaxIterations = 128
)

type argon2Param struct {
	t, m uint32
	p    uint8
	kl   uint32
}

func (a *argon2Param) getParams() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", a.m, a.t, a.p)
}

var argon2Params = map[string]argon2Param{
	argon2iHash:  {3, 32768, 4, 32},
	argon2idHash: {1, 65536, 4, 32},
}

func newArgon2Params(s string) (*argon2Param, error) {
	params := phcParamsToMap(s)
	t, err := phcAtoi(params["t"], 3)
	if err != nil || t < 1 || t > Argon2MaxIterations {
		return nil, errors.Errorf("invalid argon2 parameter t=%s", params["t"])
	}
	m, err := phcAtoi(params["m"], 12)
	if err != nil || m < 8 || m > Argon2MaxMemory {
		return nil, errors.Errorf("invalid argon2 parameter m=%s", params["m"])
	}
	p, err := phcAtoi(params["p"], 1)
	if err != nil || p < 1 || p > Argon2MaxParallelism {
		return nil, errors.Errorf("invalid argon2 parameter p=%s", params["p"])
	}

	return &argon2Param{
		t: cast.Uint32(t),
		m: cast.Uint32(m),
		p: cast.Uint8(p),
	}, nil
}
