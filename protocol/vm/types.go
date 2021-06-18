package vm

import (
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

// Uint64Bytes convert uint64 to bytes in vm
func Uint64Bytes(n uint64) []byte {
	return BigIntBytes(uint256.NewInt().SetUint64(n))
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
