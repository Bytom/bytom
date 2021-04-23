package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/bytom/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/bytom/crypto/sha3pool"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/state"
	"golang.org/x/crypto/ed25519"
)

// Verification represent a verification message for the block
// source hash and target hash point to the checkpoint, and the source checkpoint is the target checkpoint's parent(not be directly)
// the vector <sourceHash, targetHash, sourceHeight, targetHeight, pubKey> as the message of signature
type Verification struct {
	SourceHash   bc.Hash
	TargetHash   bc.Hash
	SourceHeight uint64
	TargetHeight uint64
	Signature    string
	PubKey       string
}

func makeVerification(supLink *state.SupLink, checkpoint *state.Checkpoint, pubKey string) *Verification {
	return &Verification{
		SourceHash:   supLink.SourceHash,
		TargetHash:   checkpoint.Hash,
		SourceHeight: supLink.SourceHeight,
		TargetHeight: checkpoint.Height,
		Signature:    supLink.Signatures[pubKey],
		PubKey:       pubKey,
	}
}

// toSoloSupLink convert the verification to supLink with only single signature
func (v *Verification) toSoloSupLink() *state.SupLink {
	return &state.SupLink{
		SourceHeight: v.SourceHeight,
		SourceHash:   v.SourceHash,
		Signatures:   map[string]string{v.PubKey: v.Signature},
	}
}

func (v *Verification) validate() error {
	if v.SourceHeight%state.BlocksOfEpoch != 0 || v.TargetHeight%state.BlocksOfEpoch != 0 {
		return errVoteToGrowingCheckpoint
	}

	if v.SourceHeight == v.TargetHeight {
		return errVoteToSameCheckpoint
	}

	return v.VerifySignature()
}

// EncodeMessage encode the verification for the validators to sign or verify
func (v *Verification) EncodeMessage() ([]byte, error) {
	buff := new(bytes.Buffer)
	if _, err := v.SourceHash.WriteTo(buff); err != nil {
		return nil, err
	}

	if _, err := v.TargetHash.WriteTo(buff); err != nil {
		return nil, err
	}

	uint64Buff := make([]byte, 8)

	binary.LittleEndian.PutUint64(uint64Buff, v.SourceHeight)
	if _, err := buff.Write(uint64Buff); err != nil {
		return nil, err
	}

	binary.LittleEndian.PutUint64(uint64Buff, v.TargetHeight)
	if _, err := buff.Write(uint64Buff); err != nil {
		return nil, err
	}

	return sha3Hash(buff.Bytes())
}

// Sign used to sign the verification by specified xPrv
func (v *Verification) Sign(xPrv chainkd.XPrv) error {
	message, err := v.EncodeMessage()
	if err != nil {
		return err
	}

	v.Signature = hex.EncodeToString(xPrv.Sign(message))
	return nil
}

// VerifySignature verify the signature of encode message of verification
func (v *Verification) VerifySignature() error {
	pubKey, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return err
	}

	signature, err := hex.DecodeString(v.Signature)
	if err != nil {
		return err
	}

	message, err := v.EncodeMessage()
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, message, signature) {
		return errVerifySignature
	}

	return nil
}

func sha3Hash(message []byte) ([]byte, error) {
	sha3 := sha3pool.Get256()
	defer sha3pool.Put256(sha3)

	if _, err := sha3.Write(message); err != nil {
		return nil, err
	}

	hash := &bc.Hash{}
	if _, err := hash.ReadFrom(sha3); err != nil {
		return nil, err
	}

	return hash.Bytes(), nil
}
