package database

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	dbm "github.com/bytom/bytom/database/leveldb"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
	"github.com/bytom/bytom/protocol/state"
)

const (
	colon = byte(0x3a)

	blockStore byte = iota
	blockHashes
	blockHeader
	blockTransactons
)

var (
	// BlockHashesKeyPrefix key Prefix
	BlockHashesKeyPrefix = []byte{blockHashes, colon}
	blockHeaderKeyPrefix = []byte{blockHeader, colon}
	blockTransactionsKey = []byte{blockTransactons, colon}
)

func encodeNumber(number uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf[:], number)
	return buf
}

// CalcBlockHeaderKey make up header key with prefix + hash
func CalcBlockHeaderKey(hash *bc.Hash) []byte {
	return append(blockHeaderKeyPrefix, hash.Bytes()...)
}

// CalcBlockHashesKey make up hashes key with prefix + height
func CalcBlockHashesKey(height uint64) []byte {
	return append(BlockHashesKeyPrefix, encodeNumber(height)...)
}

// CalcBlockTransactionsKey make up txs key with prefix + hash
func CalcBlockTransactionsKey(hash *bc.Hash) []byte {
	return append(blockTransactionsKey, hash.Bytes()...)
}

// CalcBlockHeaderIndexKey make up BlockHeaderIndexKey with prefix + hash
func CalcBlockHeaderIndexKey(height uint64, hash *bc.Hash) []byte {
	return append(append(BlockHeaderIndexPrefix, encodeNumber(height)...), hash.Bytes()...)
}

func rewardStatisticsKey(height uint64) []byte {
	return append(RewardStatisticsPrefix, encodeNumber(height)...)
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
	binaryHashes := db.Get(CalcBlockHashesKey(height))
	if binaryHashes == nil {
		return []*bc.Hash{}, nil
	}

	hashes := []*bc.Hash{}
	if err := json.Unmarshal(binaryHashes, &hashes); err != nil {
		return nil, err
	}
	return hashes, nil
}

// GetRewardStatistics return reward statistics by block height
func (s *Store) GetRewardStatistics(height uint64) (*state.RewardStatistics, error) {
	bytes := s.db.Get(rewardStatisticsKey(height))
	if len(bytes) == 0 {
		return nil, errors.New(fmt.Sprintf("height(%d): can't find the reward statistics", height))
	}

	rewardStatistics := new(state.RewardStatistics)
	if err := json.Unmarshal(bytes, rewardStatistics); err != nil {
		return nil, err
	}

	return rewardStatistics, nil
}
