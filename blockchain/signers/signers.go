// Package signers associates signers and their corresponding keys.
package signers

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/errors"
)

type keySpace byte

const (
	AssetKeySpace   keySpace = 0
	AccountKeySpace keySpace = 1
)

const (
	//BIP0032 compatible previous derivation rule m/account/address_index
	BIP0032 uint8 = iota
	//BIP0032 path derivation rule m/purpose'/coin_type'/account'/change/address_index
	BIP0044
)

var (
	// ErrBadQuorum is returned by Create when the quorum
	// provided is less than 1 or greater than the number
	// of xpubs provided.
	ErrBadQuorum = errors.New("quorum must be greater than or equal to 1, and must be less than or equal to the length of xpubs")

	// ErrBadXPub is returned by Create when the xpub
	// provided isn't valid.
	ErrBadXPub = errors.New("invalid xpub format")

	// ErrNoXPubs is returned by create when the xpubs
	// slice provided is empty.
	ErrNoXPubs = errors.New("at least one xpub is required")

	// ErrDupeXPub is returned by create when the same xpub
	// appears twice in a single call.
	ErrDupeXPub = errors.New("xpubs cannot contain the same key more than once")

	ErrDeriveRule = errors.New("invalid key derive rule")
)

var (
	BIP44Purpose = []byte{0x00, 0x00, 0x00, 0x2C}
	BTMCoinType  = []byte{0x00, 0x00, 0x00, 0x99}
)

// Signer is the abstract concept of a signer,
// which is composed of a set of keys as well as
// the amount of signatures needed for quorum.
type Signer struct {
	Type       string         `json:"type"`
	XPubs      []chainkd.XPub `json:"xpubs"`
	Quorum     int            `json:"quorum"`
	KeyIndex   uint64         `json:"key_index"`
	DeriveRule uint8          `json:"derive_rule"`
}

func getBip0032Path(accountIndex uint64, ks keySpace, addrIndex uint64) [][]byte {
	var path [][]byte
	signerPath := [9]byte{byte(ks)}
	binary.LittleEndian.PutUint64(signerPath[1:], accountIndex)
	path = append(path, signerPath[:])
	var idxBytes [8]byte
	binary.LittleEndian.PutUint64(idxBytes[:], addrIndex)
	path = append(path, idxBytes[:])
	return path
}

// Path returns the complete path for derived keys
func getBip0044Path(accountIndex uint64, change bool, addrIndex uint64) [][]byte {
	var path [][]byte
	path = append(path, BIP44Purpose[:]) //purpose
	path = append(path, BTMCoinType[:])  //coin type
	accIdxBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(accIdxBytes, uint64(accountIndex))
	path = append(path, accIdxBytes) //account index
	branchBytes := make([]byte, 8)
	if change {
		binary.LittleEndian.PutUint64(branchBytes, uint64(1))
	} else {
		binary.LittleEndian.PutUint64(branchBytes, uint64(0))
	}
	path = append(path, branchBytes) //change
	addrIdxBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrIdxBytes[:], addrIndex)
	path = append(path, addrIdxBytes[:]) //address index
	return path
}

// Path returns the complete path for derived keys
func Path(s *Signer, ks keySpace, change bool, addrIndex uint64) ([][]byte, error) {
	switch s.DeriveRule {
	case BIP0032:
		return getBip0032Path(s.KeyIndex, ks, addrIndex), nil
	case BIP0044:
		return getBip0044Path(s.KeyIndex, change, addrIndex), nil
	}
	return nil, ErrDeriveRule
}

// Create creates and stores a Signer in the database
func Create(signerType string, xpubs []chainkd.XPub, quorum int, keyIndex uint64, deriveRule uint8) (*Signer, error) {
	if len(xpubs) == 0 {
		return nil, errors.Wrap(ErrNoXPubs)
	}

	sort.Sort(SortKeys(xpubs)) // this transforms the input slice
	for i := 1; i < len(xpubs); i++ {
		if bytes.Equal(xpubs[i][:], xpubs[i-1][:]) {
			return nil, errors.WithDetailf(ErrDupeXPub, "duplicated key=%x", xpubs[i])
		}
	}

	if quorum == 0 || quorum > len(xpubs) {
		return nil, errors.Wrap(ErrBadQuorum)
	}

	return &Signer{
		Type:       signerType,
		XPubs:      xpubs,
		Quorum:     quorum,
		KeyIndex:   keyIndex,
		DeriveRule: deriveRule,
	}, nil
}

type SortKeys []chainkd.XPub

func (s SortKeys) Len() int           { return len(s) }
func (s SortKeys) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s SortKeys) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
