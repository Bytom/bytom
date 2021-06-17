package vm

import (
	"encoding/binary"

	"github.com/holiman/uint256"
)

var trueBytes = []byte{1}

// BoolBytes convert bool to bytes
func BoolBytes(b bool) (result []byte) {
	if b {
		return trueBytes
	}
	return []byte{}
}

// AsBool convert bytes to bool
func AsBool(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return true
		}
	}
	return false
}

// Int64Bytes convert int64 to bytes
func Int64Bytes(n int64) []byte {
	if n == 0 {
		return []byte{}
	}
	res := make([]byte, 8)
	// converting int64 to uint64 is a safe operation that
	// preserves all data
	binary.LittleEndian.PutUint64(res, uint64(n))
	for len(res) > 0 && res[len(res)-1] == 0 {
		res = res[:len(res)-1]
	}
	return res
}

// BigIntBytes conv big int to little endian bytes, uint256 is version 1.1.1
func BigIntBytes(n *uint256.Int) []byte {
	return reverse(n.Bytes())
}

// AsBigInt conv little endian bytes to big int
func AsBigInt(b []byte) (*uint256.Int, error) {
	if len(b) > 32 {
		return nil, ErrBadValue
	}

	res := uint256.NewInt().SetBytes(reverse(b))
	if res.Sign() < 0 {
		return nil, ErrRange
	}

	return res, nil
}

// reverse []byte.
func reverse(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}

	return b
}
