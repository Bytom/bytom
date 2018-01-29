package difficulty

// HashToBig converts a *bc.Hash into a big.Int that can be used to
import (
	"fmt"
	"math/big"

	"github.com/bytom/consensus"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/legacy"
)

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// oneLsh256 is 1 shifted left 256 bits.  It is defined here to avoid
	// the overhead of creating it multiple times.
	oneLsh256 = new(big.Int).Lsh(bigOne, 256)
)

// HashToBig convert bc.Hash to a difficult int
func HashToBig(hash *bc.Hash) *big.Int {
	buf := hash.Byte32()
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	return new(big.Int).SetBytes(buf[:])
}

// CompactToBig converts a compact representation of a whole number N to an
// unsigned 64-bit number.  The representation is similar to IEEE754 floating
// point numbers.
//
//	-------------------------------------------------
//	|   Exponent     |    Sign    |    Mantissa     |
//	-------------------------------------------------
//	| 8 bits [63-56] | 1 bit [55] | 55 bits [54-00] |
//	-------------------------------------------------
//
// 	N = (-1^sign) * mantissa * 256^(exponent-3)
func CompactToBig(compact uint64) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffffffffffff
	isNegative := compact&0x0080000000000000 != 0
	exponent := uint(compact >> 56)

	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

// BigToCompact converts a whole number N to a compact representation using
// an unsigned 64-bit number
func BigToCompact(n *big.Int) uint64 {
	if n.Sign() == 0 {
		return 0
	}

	var mantissa uint64
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint64(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		tn := new(big.Int).Set(n)
		mantissa = uint64(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	if mantissa&0x0080000000000000 != 0 {
		mantissa >>= 8
		exponent++
	}

	compact := uint64(exponent<<56) | mantissa
	if n.Sign() < 0 {
		compact |= 0x0080000000000000
	}
	return compact
}

// CalcWork calculates a work value from difficulty bits.  Bitcoin increases
// the difficulty for generating a block by decreasing the value which the
// generated hash must be less than.  This difficulty target is stored in each
// block header using a compact representation as described in the documentation
// for CompactToBig.  The main chain is selected by choosing the chain that has
// the most proof of work (highest difficulty).  Since a lower target difficulty
// value equates to higher actual difficulty, the work value which will be
// accumulated must be the inverse of the difficulty.  Also, in order to avoid
// potential division by zero and really small floating point numbers, the
// result adds 1 to the denominator and multiplies the numerator by 2^256.
func CalcWork(bits uint64) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	fmt.Printf("--------difficultyNum:%v\n", difficultyNum)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

// CheckProofOfWork the hash is valid for given difficult
func CheckProofOfWork(hash *bc.Hash, bits uint64) bool {
	// fmt.Printf("hash bigint:%v, bits bigint:%v\n", HashToBig(hash), CalcWork(bits))
	fmt.Printf("hash bigint:%v, bits bigint:%v\n", HashToBig(hash), CompactToBig(bits))
	// return HashToBig(hash).Cmp(CalcWork(bits)) <= 0
	return HashToBig(hash).Cmp(CompactToBig(bits)) <= 0
}

// CalcNextRequiredDifficulty return the difficult for next block
func CalcNextRequiredDifficulty(lastBH, compareBH *legacy.BlockHeader) uint64 {
	// return lastBH.Bits
	if lastBH == nil {
		return consensus.PowMinBits
	} else if (lastBH.Height)%consensus.BlocksPerRetarget != 0 || lastBH.Height == 0 {
		return lastBH.Bits
	}

	targetTimeSpan := int64(consensus.BlocksPerRetarget * consensus.TargetSecondsPerBlock)
	actualTimeSpan := int64(lastBH.Timestamp - compareBH.Timestamp)

	oldTarget := CompactToBig(lastBH.Bits)
	// oldTarget := CalcWork(lastBH.Bits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(actualTimeSpan))
	newTarget.Div(newTarget, big.NewInt(targetTimeSpan))
	newTargetBits := BigToCompact(newTarget)

	return newTargetBits
}
