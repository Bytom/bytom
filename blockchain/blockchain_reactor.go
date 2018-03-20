package blockchain

import (
	log "github.com/sirupsen/logrus"

	"github.com/bytom/blockchain/query"
	"github.com/bytom/blockchain/wallet"
	"github.com/bytom/consensus"
	"github.com/bytom/consensus/difficulty"
	chainjson "github.com/bytom/encoding/json"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
)

// return network infomation
func (bcr *BlockchainReactor) getNetInfo() Response {
	type netInfo struct {
		Listening    bool   `json:"listening"`
		Syncing      bool   `json:"syncing"`
		Mining       bool   `json:"mining"`
		PeerCount    int    `json:"peer_count"`
		CurrentBlock uint64 `json:"current_block"`
		HighestBlock uint64 `json:"highest_block"`
	}
	net := &netInfo{}
	net.Listening = bcr.sw.IsListening()
	net.Syncing = bcr.blockKeeper.IsCaughtUp()
	net.Mining = bcr.mining.IsMining()
	net.PeerCount = len(bcr.sw.Peers().List())
	net.CurrentBlock = bcr.blockKeeper.chainHeight
	net.HighestBlock = bcr.blockKeeper.maxPeerHeight

	return NewSuccessResponse(net)
}

// return best block hash
func (bcr *BlockchainReactor) getBestBlockHash() Response {
	blockHash := map[string]string{"blockHash": bcr.chain.BestBlockHash().String()}
	return NewSuccessResponse(blockHash)
}

// return block header by hash
func (bcr *BlockchainReactor) getBlockHeaderByHash(strHash string) Response {
	hash := bc.Hash{}
	if err := hash.UnmarshalText([]byte(strHash)); err != nil {
		log.WithField("error", err).Error("Error occurs when transforming string hash to hash struct")
		return NewErrorResponse(err)
	}
	block, err := bcr.chain.GetBlockByHash(&hash)
	if err != nil {
		log.WithField("error", err).Error("Fail to get block by hash")
		return NewErrorResponse(err)
	}

	bcBlock := types.MapBlock(block)
	return NewSuccessResponse(bcBlock.BlockHeader)
}

type BlockTx struct {
	ID         bc.Hash                  `json:"id"`
	Version    uint64                   `json:"version"`
	Size       uint64                   `json:"size"`
	TimeRange  uint64                   `json:"time_range"`
	Inputs     []*query.AnnotatedInput  `json:"inputs"`
	Outputs    []*query.AnnotatedOutput `json:"outputs"`
	StatusFail bool                     `json:"status_fail"`
}

type GetBlockReq struct {
	BlockHeight uint64             `json:"block_height"`
	BlockHash   chainjson.HexBytes `json:"block_hash"`
}

type GetBlockResp struct {
	Hash                   *bc.Hash   `json:"hash"`
	Size                   uint64     `json:"size"`
	Version                uint64     `json:"version"`
	Height                 uint64     `json:"height"`
	PreviousBlockHash      *bc.Hash   `json:"previous_block_hash"`
	Timestamp              uint64     `json:"timestamp"`
	Nonce                  uint64     `json:"nonce"`
	Bits                   uint64     `json:"bits"`
	Difficulty             string     `json:"difficulty"`
	TransactionsMerkleRoot *bc.Hash   `json:"transaction_merkle_root"`
	TransactionStatusHash  *bc.Hash   `json:"transaction_status_hash"`
	Transactions           []*BlockTx `json:"transactions"`
}

// return block by hash
func (bcr *BlockchainReactor) getBlock(ins GetBlockReq) Response {
	var err error
	block := &types.Block{}
	if len(ins.BlockHash) == 32 {
		b32 := [32]byte{}
		copy(b32[:], ins.BlockHash)
		hash := bc.NewHash(b32)
		block, err = bcr.chain.GetBlockByHash(&hash)
	} else {
		block, err = bcr.chain.GetBlockByHeight(ins.BlockHeight)
	}
	if err != nil {
		return NewErrorResponse(err)
	}

	blockHash := block.Hash()
	txStatus, err := bcr.chain.GetTransactionStatus(&blockHash)
	rawBlock, err := block.MarshalText()
	if err != nil {
		return NewErrorResponse(err)
	}

	resp := &GetBlockResp{
		Hash:                   &blockHash,
		Size:                   uint64(len(rawBlock)),
		Version:                block.Version,
		Height:                 block.Height,
		PreviousBlockHash:      &block.PreviousBlockHash,
		Timestamp:              block.Timestamp,
		Nonce:                  block.Nonce,
		Bits:                   block.Bits,
		Difficulty:             difficulty.CompactToBig(block.Bits).String(),
		TransactionsMerkleRoot: &block.TransactionsMerkleRoot,
		TransactionStatusHash:  &block.TransactionStatusHash,
		Transactions:           []*BlockTx{},
	}

	for i, orig := range block.Transactions {
		tx := &BlockTx{
			ID:        orig.ID,
			Version:   orig.Version,
			Size:      orig.SerializedSize,
			TimeRange: orig.TimeRange,
			Inputs:    []*query.AnnotatedInput{},
			Outputs:   []*query.AnnotatedOutput{},
		}
		tx.StatusFail, err = txStatus.GetStatus(i)
		if err != nil {
			NewSuccessResponse(resp)
		}

		for i := range orig.Inputs {
			tx.Inputs = append(tx.Inputs, wallet.BuildAnnotatedInput(orig, uint32(i)))
		}
		for i := range orig.Outputs {
			tx.Outputs = append(tx.Outputs, wallet.BuildAnnotatedOutput(orig, i))
		}
		resp.Transactions = append(resp.Transactions, tx)
	}
	return NewSuccessResponse(resp)
}

// return block transactions count by hash
func (bcr *BlockchainReactor) getBlockTransactionsCountByHash(strHash string) Response {
	hash := bc.Hash{}
	if err := hash.UnmarshalText([]byte(strHash)); err != nil {
		log.WithField("error", err).Error("Error occurs when transforming string hash to hash struct")
		return NewErrorResponse(err)
	}

	legacyBlock, err := bcr.chain.GetBlockByHash(&hash)
	if err != nil {
		log.WithField("error", err).Error("Fail to get block by hash")
		return NewErrorResponse(err)
	}

	count := map[string]int{"count": len(legacyBlock.Transactions)}
	return NewSuccessResponse(count)
}

// return block transactions count by height
func (bcr *BlockchainReactor) getBlockTransactionsCountByHeight(height uint64) Response {
	legacyBlock, err := bcr.chain.GetBlockByHeight(height)
	if err != nil {
		log.WithField("error", err).Error("Fail to get block by hash")
		return NewErrorResponse(err)
	}

	count := map[string]int{"count": len(legacyBlock.Transactions)}
	return NewSuccessResponse(count)
}

// return block height
func (bcr *BlockchainReactor) blockHeight() Response {
	blockHeight := map[string]uint64{"blockHeight": bcr.chain.Height()}
	return NewSuccessResponse(blockHeight)
}

// return is in mining or not
func (bcr *BlockchainReactor) isMining() Response {
	IsMining := map[string]bool{"isMining": bcr.mining.IsMining()}
	return NewSuccessResponse(IsMining)
}

// return gasRate
func (bcr *BlockchainReactor) gasRate() Response {
	gasrate := map[string]int64{"gasRate": consensus.VMGasRate}
	return NewSuccessResponse(gasrate)
}
