package database

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	dbm "github.com/bytom/bytom/database/leveldb"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
)

const (
	colon = byte(0x3a)

	blockStore byte = iota
	blockHashes
	blockHeader
	blockTransactons
)

func CalcBlockHeaderKey(hash *bc.Hash) []byte {
	return append([]byte{blockHeader, colon}, hash.Bytes()...)
}

func CalcBlockHashesPrefix(height uint64) []byte {
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], height)
	return append(BlockHashesPrefix(), buf[:]...)
}

func BlockHashesPrefix() []byte {
	return []byte{blockHashes, colon}
}

func CalcBlockTransactionsKey(hash *bc.Hash) []byte {
	return append([]byte{blockTransactons, colon}, hash.Bytes()...)
}

func CalcBlockKey(hash *bc.Hash) []byte {
	return append(BlockPrefix, hash.Bytes()...)
}

func CalcBlockHeaderIndexKey(height uint64, hash *bc.Hash) []byte {
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], height)
	key := append(BlockHeaderIndexPrefix, buf[:]...)
	return append(key, hash.Bytes()...)
}

// GetBlockHeader return the block header by given hash
func GetBlockHeader(db dbm.DB, hash *bc.Hash) (*types.BlockHeader, error) {
	binaryBlockHeader := db.Get(CalcBlockHeaderKey(hash))
	if binaryBlockHeader == nil {
		return nil, fmt.Errorf("There are no blockHeader with given hash %s", hash.String())
	}

	blockHeader := &types.BlockHeader{}
	if err := blockHeader.UnmarshalText(binaryBlockHeader); err != nil {
		return nil, err
	}
	return blockHeader, nil
}

// GetBlockTransactions return the block transactions by given hash
func GetBlockTransactions(db dbm.DB, hash *bc.Hash) ([]*types.Tx, error) {
	binaryBlockTxs := db.Get(CalcBlockTransactionsKey(hash))
	if binaryBlockTxs == nil {
		return nil, fmt.Errorf("There are no block transactions with given hash %s", hash.String())
	}

	block := &types.Block{}
	if err := block.UnmarshalText(binaryBlockTxs); err != nil {
		return nil, err
	}
	return block.Transactions, nil
}

// GetBlockHashesByHeight return block hashes by given height
func GetBlockHashesByHeight(db dbm.DB, height uint64) ([]*bc.Hash, error) {
	binaryHashes := db.Get(CalcBlockHashesPrefix(height))
	if binaryHashes == nil {
		return []*bc.Hash{}, nil
	}

	hashes := []*bc.Hash{}
	if err := json.Unmarshal(binaryHashes, &hashes); err != nil {
		return nil, err
	}
	return hashes, nil
}

// GetBlock return the block by given hash
func GetBlock(db dbm.DB, hash *bc.Hash) (*types.Block, error) {
	bytez := db.Get(CalcBlockKey(hash))
	if bytez == nil {
		return nil, nil
	}

	block := &types.Block{}
	err := block.UnmarshalText(bytez)
	return block, err
}

// SaveBlockHeader persists a new block header in the protocol.
func (s *Store) SaveBlockHeader(blockHeader *types.BlockHeader) error {
	binaryBlockHeader, err := blockHeader.MarshalText()
	if err != nil {
		return errors.Wrap(err, "Marshal block header")
	}

	blockHash := blockHeader.Hash()
	s.db.Set(CalcBlockHeaderKey(&blockHash), binaryBlockHeader)
	s.cache.removeBlockHeader(blockHeader)
	return nil
}

// GetBlockHashesByHeight return the block hash by the specified height
func (s *Store) GetBlockHashesByHeight(height uint64) ([]*bc.Hash, error) {
	return s.cache.lookupBlockHashesByHeight(height)
}

// SaveBlock persists a new block in the protocol.
func (s *Store) SaveBlock(block *types.Block) error {
	startTime := time.Now()
	binaryBlockHeader, err := block.MarshalTextForBlockHeader()
	if err != nil {
		return errors.Wrap(err, "Marshal block header")
	}

	binaryBlockTxs, err := block.MarshalTextForTransactions()
	if err != nil {
		return errors.Wrap(err, "Marshal block transactions")
	}

	blockHashes := []*bc.Hash{}
	hashes, err := s.GetBlockHashesByHeight(block.Height)
	if err != nil {
		return err
	}

	blockHashes = append(blockHashes, hashes...)
	blockHash := block.Hash()
	blockHashes = append(blockHashes, &blockHash)
	binaryBlockHashes, err := json.Marshal(blockHashes)
	if err != nil {
		return errors.Wrap(err, "Marshal block hashes")
	}

	batch := s.db.NewBatch()
	batch.Set(CalcBlockHashesPrefix(block.Height), binaryBlockHashes)
	batch.Set(CalcBlockHeaderKey(&blockHash), binaryBlockHeader)
	batch.Set(CalcBlockTransactionsKey(&blockHash), binaryBlockTxs)
	batch.Set(CalcBlockHeaderIndexKey(block.Height, &blockHash), binaryBlockHeader)
	batch.Write()

	s.cache.removeBlockHashes(block.Height)
	log.WithFields(log.Fields{
		"module":   logModule,
		"height":   block.Height,
		"hash":     blockHash.String(),
		"duration": time.Since(startTime),
	}).Info("block saved on disk")
	return nil
}

// GetBlockTransactions return the Block transactions by given hash
func (s *Store) GetBlockTransactions(hash *bc.Hash) ([]*types.Tx, error) {
	return s.cache.lookupBlockTxs(hash)
}

// GetBlock return the block by given hash
func (s *Store) GetBlock(hash *bc.Hash) (*types.Block, error) {
	blockHeader, err := s.GetBlockHeader(hash)
	if err != nil {
		return nil, err
	}

	txs, err := s.GetBlockTransactions(hash)
	if err != nil {
		return nil, err
	}

	return &types.Block{
		BlockHeader:  *blockHeader,
		Transactions: txs,
	}, nil
}
