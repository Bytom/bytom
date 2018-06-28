package sm2

import (
	"math/big"
)

// VerifyBytes verify sigature is valid.
// The parameters is bytes.
func VerifyBytes(pubX, pubY, msg, uid, r, s []byte) bool {
	pub := &PublicKey{
		Curve: P256Sm2(),
		X:     new(big.Int).SetBytes(pubX),
		Y:     new(big.Int).SetBytes(pubY),
	}
	bigR := new(big.Int).SetBytes(r)
	bigS := new(big.Int).SetBytes(s)

	c := P256Sm2()
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if bigR.Cmp(one) < 0 || bigS.Cmp(one) < 0 {
		return false
	}
	if bigR.Cmp(N) >= 0 || bigS.Cmp(N) >= 0 {
		return false
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	t := new(big.Int).Add(bigR, bigS)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(bigS.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(bigR) == 0
}
