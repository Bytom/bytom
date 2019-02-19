package wire

import (
	"io"
	"math"

	cmn "github.com/tendermint/tmlibs/common"
)

func WriteByteSlice(bz []byte, w io.Writer, n *int, err *error) {
	WriteVarint(len(bz), w, n, err)
	WriteTo(bz, w, n, err)
}

func ReadByteSlice(r io.Reader, lmt int, n *int, err *error) []byte {
	length := ReadVarint(r, n, err)
	if *err != nil {
		return nil
	}
	if length < 0 {
		*err = ErrBinaryReadInvalidLength
		return nil
	}

	// check that length is less than the maximum slice size
	if length > math.MaxInt32 {
		*err = ErrBinaryReadOverflow
		return nil
	}
	if lmt != 0 && lmt < cmn.MaxInt(length, *n+length) {
		*err = ErrBinaryReadOverflow
		return nil
	}

	/*	if length == 0 {
		return nil // zero value for []byte
	}*/

	buf := make([]byte, length)
	ReadFull(buf, r, n, err)
	return buf

}

func PutByteSlice(buf []byte, bz []byte) (n int, err error) {
	n_, err := PutVarint(buf, len(bz))
	if err != nil {
		return 0, err
	}
	buf = buf[n_:]
	n += n_
	if len(buf) < len(bz) {
		return 0, ErrBinaryWriteOverflow
	}
	copy(buf, bz)
	return n + len(bz), nil
}
