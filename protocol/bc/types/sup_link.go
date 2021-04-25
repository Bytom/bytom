package types

import (
	"io"

	"github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/encoding/blockchain"
	"github.com/bytom/bytom/protocol/bc"
)

// SupLinks is alias of SupLink slice
type SupLinks []*SupLink

func (s *SupLinks) readFrom(r *blockchain.Reader) (err error) {
	size, err := blockchain.ReadVarint31(r)
	if err != nil {
		return err
	}

	supLinks := make([]*SupLink, size)
	for i := 0; i < int(size); i++ {
		supLink := &SupLink{}
		if err := supLink.readFrom(r); err != nil {
			return err
		}

		supLinks[i] = supLink
	}
	*s = supLinks
	return nil
}

func (s SupLinks) writeTo(w io.Writer) error {
	if _, err := blockchain.WriteVarint31(w, uint64(len(s))); err != nil {
		return err
	}

	for _, supLink := range s {
		if err := supLink.writeTo(w); err != nil {
			return err
		}
	}
	return nil
}

// SupLink is an ordered pair of checkpoints (a, b), also written a → b
// the validators will sign it once considered as legal
type SupLink struct {
	SourceHeight uint64
	SourceHash   bc.Hash
	Signatures   [consensus.NumOfValidators][]byte
}

func (s *SupLink) readFrom(r *blockchain.Reader) (err error) {
	if s.SourceHeight, err = blockchain.ReadVarint63(r); err != nil {
		return err
	}

	if _, err := s.SourceHash.ReadFrom(r); err != nil {
		return err
	}

	for i := 0; i < consensus.NumOfValidators; i++ {
		if s.Signatures[i], err = blockchain.ReadVarstr31(r); err != nil {
			return err
		}
	}
	return
}

func (s *SupLink) writeTo(w io.Writer) error {
	if _, err := blockchain.WriteVarint63(w, s.SourceHeight); err != nil {
		return err
	}

	if _, err := s.SourceHash.WriteTo(w); err != nil {
		return err
	}

	for _, signature := range s.Signatures {
		if _, err := blockchain.WriteVarstr31(w, signature); err != nil {
			return err
		}
	}
	return nil
}
