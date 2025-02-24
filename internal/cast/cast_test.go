package cast_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smallstep/cli/internal/cast"
)

func TestUintConvertsValues(t *testing.T) {
	require.Equal(t, uint(0), cast.Uint(0))
	require.Equal(t, uint(math.MaxInt), cast.Uint(math.MaxInt))
	require.Equal(t, uint(42), cast.Uint(42))
}

func TestUintPanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint(-1) })
}

func TestIntConvertsValues(t *testing.T) {
	require.Equal(t, int(0), cast.Int(0))
	require.Equal(t, int(math.MaxInt), cast.Int(math.MaxInt))
	require.Equal(t, int(42), cast.Int(42))
}

func TestIntPanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { cast.Int(uint(math.MaxInt + 1)) })
}

func TestInt64ConvertsValues(t *testing.T) {
	require.Equal(t, int64(0), cast.Int64(0))
	require.Equal(t, int64(math.MaxInt), cast.Int64(math.MaxInt))
	require.Equal(t, int64(42), cast.Int64(42))
}

func TestInt64PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { cast.Int64(uint64(math.MaxInt64 + 1)) })
}

func TestUint64ConvertsValues(t *testing.T) {
	require.Equal(t, uint64(0), cast.Uint64(0))
	require.Equal(t, uint64(math.MaxInt), cast.Uint64((math.MaxInt)))
	require.Equal(t, uint64(42), cast.Uint64(42))
}

func TestUint64PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint64(-1) })
}

func TestInt32ConvertsValues(t *testing.T) {
	require.Equal(t, int32(0), cast.Int32(0))
	require.Equal(t, int32(math.MaxInt32), cast.Int32(math.MaxInt32))
	require.Equal(t, int32(42), cast.Int32(42))
}

func TestInt32PanicsOnTooSmallValue(t *testing.T) {
	require.Panics(t, func() { cast.Int32(int64(math.MinInt32 - 1)) })
}

func TestInt32PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { cast.Int32(int64(math.MaxInt32 + 1)) })
}

func TestUint32ConvertsValues(t *testing.T) {
	require.Equal(t, uint32(0), cast.Uint32(0))
	require.Equal(t, uint32(math.MaxUint32), cast.Uint32(int64(math.MaxUint32)))
	require.Equal(t, uint32(42), cast.Uint32(42))
}

func TestUint32PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint32(-1) })
}

func TestUint32PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint32(int64(math.MaxUint32 + 1)) })
}

func TestUint8ConvertsValues(t *testing.T) {
	require.Equal(t, uint8(0), cast.Uint8(0))
	require.Equal(t, uint8(math.MaxUint8), cast.Uint8(math.MaxUint8))
	require.Equal(t, uint8(42), cast.Uint8(42))
}

func TestUint8PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint8(-1) })
}

func TestUint8PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { cast.Uint8(math.MaxUint8 + 1) })
}
