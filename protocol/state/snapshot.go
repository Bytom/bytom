package state

import (
	"fmt"

	"github.com/bytom/errors"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/patricia"
)

// Snapshot encompasses a snapshot of entire blockchain state. It
// consists of a patricia state tree and the nonce set.
//
// Nonces maps a nonce entry's ID to the time (in Unix millis) at
// which it should expire from the nonce set.
//
// TODO: consider making type Snapshot truly immutable.  We already
// handle it that way in many places (with explicit calls to Copy to
// get the right behavior).  PruneNonces and the Apply functions would
// have to produce new Snapshots rather than updating Snapshots in
// place.
type Snapshot struct {
	Tree   *patricia.Tree
	Nonces map[bc.Hash]uint64
}

// PruneNonces modifies a Snapshot, removing all nonce IDs with
// expiration times earlier than the provided timestamp.
func (s *Snapshot) PruneNonces(timestampMS uint64) {
	for hash, expiryMS := range s.Nonces {
		if timestampMS > expiryMS {
			delete(s.Nonces, hash)
		}
	}
}

// Copy makes a copy of provided snapshot. Copying a snapshot is an
// O(n) operation where n is the number of nonces in the snapshot's
// nonce set.
func Copy(original *Snapshot) *Snapshot {
	c := &Snapshot{
		Tree:   new(patricia.Tree),
		Nonces: make(map[bc.Hash]uint64, len(original.Nonces)),
	}
	*c.Tree = *original.Tree
	for k, v := range original.Nonces {
		c.Nonces[k] = v
	}
	return c
}

// Empty returns an empty state snapshot.
func Empty() *Snapshot {
	return &Snapshot{
		Tree:   new(patricia.Tree),
		Nonces: make(map[bc.Hash]uint64),
	}
}

// ApplyBlock updates s in place.
func (s *Snapshot) ApplyBlock(block *bc.Block) error {
	for i, tx := range block.Transactions {
		if err := s.ApplyTx(tx); err != nil {
			return errors.Wrapf(err, "applying block transaction %d", i)
		}
	}
	return nil
}

// ApplyTx updates s in place.
func (s *Snapshot) ApplyTx(tx *bc.Tx) error {
	for _, n := range tx.NonceIDs {
		// Add new nonces. They must not conflict with nonces already
		// present.
		if _, ok := s.Nonces[n]; ok {
			return fmt.Errorf("conflicting nonce %x", n.Bytes())
		}

		s.Nonces[n] = 0
	}

	// Remove spent outputs. Each output must be present.
	for _, prevout := range tx.SpentOutputIDs {
		if !s.Tree.Contains(prevout.Bytes()) {
			return fmt.Errorf("invalid prevout %x", prevout.Bytes())
		}
		s.Tree.Delete(prevout.Bytes())
	}

	// Add new outputs. They must not yet be present.
	for _, id := range tx.TxHeader.ResultIds {
		// Ensure that this result is an output. It could be a retirement
		// which should not be inserted into the state tree.
		e := tx.Entries[*id]
		if _, ok := e.(*bc.Output); !ok {
			continue
		}

		err := s.Tree.Insert(id.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Snapshot) DetachBlock(block *bc.Block) error {
	for i, tx := range block.Transactions {
		err := s.DetachTx(tx)
		if err != nil {
			return errors.Wrapf(err, "detachTx block transaction %d", i)
		}
	}
	return nil
}

func (s *Snapshot) DetachTx(tx *bc.Tx) error {
	for _, n := range tx.NonceIDs {
		delete(s.Nonces, n)
	}

	for _, prevout := range tx.SpentOutputIDs {
		if s.Tree.Contains(prevout.Bytes()) {
			return fmt.Errorf("invalid prevout %x", prevout.Bytes())
		}
		if err := s.Tree.Insert(prevout.Bytes()); err != nil {
			return err
		}
	}

	for _, id := range tx.TxHeader.ResultIds {
		e := tx.Entries[*id]
		if _, ok := e.(*bc.Output); !ok {
			continue
		}

		s.Tree.Delete(id.Bytes())
	}
	return nil
}
