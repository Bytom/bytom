package utxo_view

import (
	"encoding/hex"

	"github.com/bytom/consensus"
	"github.com/bytom/consensus/difficulty"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
	"github.com/bytom/protocol/state"
	"github.com/bytom/testutil"
)

const utxoPreFix = "UT:"

func calcUtxoKey(hash *bc.Hash) []byte {
	return []byte(utxoPreFix + hash.String())
}

type tx struct {
	Tx *types.Tx
}

func newTx(t *types.Tx) *tx {
	return &tx{
		Tx: t,
	}
}

func (t *tx) getSourceID(outIndex int) *bc.Hash {
	output := t.Tx.Entries[*t.Tx.OutputID(outIndex)].(*bc.Output)
	return output.Source.Ref
}

func (t *tx) getAmount(outIndex int) uint64 {
	output := t.Tx.Entries[*t.Tx.OutputID(outIndex)].(*bc.Output)
	return output.Source.Value.Amount
}

func (t *tx) getSpentOutputID() bc.Hash {
	return t.Tx.SpentOutputIDs[0]
}

func (t *tx) OutputHash(outIndex int) *bc.Hash {
	return t.Tx.ResultIds[outIndex]
}

func blockNode(header *bc.BlockHeader) *state.BlockNode {
	h := types.BlockHeader{
		Version:           header.Version,
		Height:            header.Height,
		PreviousBlockHash: *header.PreviousBlockId,
		Timestamp:         header.Timestamp,
		Bits:              header.Bits,
		Nonce:             header.Nonce,
	}
	return &state.BlockNode{
		Parent:    nil,
		Hash:      h.Hash(),
		WorkSum:   difficulty.CalcWork(h.Bits),
		Version:   h.Version,
		Height:    h.Height,
		Timestamp: h.Timestamp,
		Nonce:     h.Nonce,
		Bits:      h.Bits,
	}
}

func mustDecodeHex(str string) []byte {
	data, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return data
}

func coinBaseTx(amount uint64) *types.Tx {
	return types.NewTx(types.TxData{
		Inputs: []*types.TxInput{
			types.NewCoinbaseInput([]byte("arbitrary")),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(*consensus.BTMAssetID, amount, mustDecodeHex("00144431c4278632c6e35dd2870faa1a4b8e0a275cbc")),
		},
	})
}

func spendTx(hash string, amount, sourcePos uint64) *types.Tx {
	sourceID := bc.Hash{}
	sourceID.UnmarshalText([]byte(hash))
	return types.NewTx(types.TxData{
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, sourceID, *consensus.BTMAssetID, amount, sourcePos, []byte("00144431c4278632c6e35dd2870faa1a4b8e0a275cbc")),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(*consensus.BTMAssetID, 100000000, []byte("00148c704747e94387fa0b8712b053ed2132d84820ac")),
			types.NewTxOutput(*consensus.BTMAssetID, amount-100000000, []byte("00144431c4278632c6e35dd2870faa1a4b8e0a275cbc")),
		},
	})
}

var mockTransaction = []*tx{
	&tx{
		Tx: coinBaseTx(41250000000),
	},
	&tx{
		Tx: spendTx("ca9b179e549406aa583869e124e39817414d4500a8ce5476e95b6018d182b966", 41250000000, 0),
	},
	&tx{
		Tx: spendTx("ca9b179e549406aa583869e124e39817414d4500a8ce5476e95b6018d182b966", 41250000000, 0),
	},
	&tx{
		Tx: spendTx("ca9b179e549406aa583869e124e39817414d4500a8ce5476e95b6018d182b966", 41250000000, 0),
	},
	&tx{
		Tx: spendTx("ca9b179e549406aa583869e124e39817414d4500a8ce5476e95b6018d182b966", 41250000000, 0),
	},
}

var chainTx1 = &tx{
	Tx: spendTx(mockTransaction[1].getSourceID(1).String(), mockTransaction[1].getAmount(1), 1),
}

var chainTx2 = &tx{
	Tx: spendTx(chainTx1.getSourceID(1).String(), chainTx1.getAmount(1), 1),
}

type block struct {
	types.Block
}

var mockBlocks = []*block{
	// coinbase tx
	&block{Block: types.Block{
		BlockHeader: types.BlockHeader{
			Height:            100,
			PreviousBlockHash: testutil.MustDecodeHash("0ab29c0bd7bff3b3b7eb98802f8d5f8833884c86c0fb21559a65cc58dda99667"),
			Timestamp:         1522908275,
			Nonce:             0,
		},
		Transactions: []*types.Tx{
			coinBaseTx(41250000000),
		},
	}},

	// Chain trading 3
	&block{Block: types.Block{
		BlockHeader: types.BlockHeader{
			Height:            101,
			PreviousBlockHash: testutil.MustDecodeHash("0ab29c0bd7bff3b3b7eb98802f8d5f8833884c86c0fb21559a65cc58dda99667"),
			Timestamp:         1522908275,
			Nonce:             0,
		},
		Transactions: []*types.Tx{
			mockTransaction[0].Tx,
			mockTransaction[1].Tx,
			chainTx1.Tx,
			chainTx2.Tx,
		},
	}},
}
