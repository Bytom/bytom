package validation

import (
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
	"github.com/bytom/bytom/protocol/state"
	"github.com/bytom/bytom/protocol/vm/vmutil"
)

func TestCheckBlockTime(t *testing.T) {
	cases := []struct {
		desc       string
		blockTime  uint64
		parentTime []uint64
		err        error
	}{
		{
			blockTime:  1520006000,
			parentTime: []uint64{1520000000},
			err:        nil,
		},
		{
			desc:       "timestamp less than past median time",
			blockTime:  1520006000,
			parentTime: []uint64{1520000000, 1520000500, 1520001000, 1520001500, 1520002000, 1520002500, 1520003000, 1520003500, 1520004000, 1520004500, 1520005000},
			err:        nil,
		},
		{
			desc:       "timestamp greater than max limit",
			blockTime:  99999999990000,
			parentTime: []uint64{15200000000000},
			err:        errBadTimestamp,
		},
		{
			desc:       "timestamp of the block and the parent block are both greater than max limit",
			blockTime:  uint64(time.Now().UnixNano()/int64(time.Millisecond)) + consensus.ActiveNetParams.MaxTimeOffsetMs + 2000,
			parentTime: []uint64{uint64(time.Now().UnixNano()/int64(time.Millisecond)) + consensus.ActiveNetParams.MaxTimeOffsetMs + 1000},
			err:        errBadTimestamp,
		},
	}

	parent := &types.BlockHeader{Version: 1}
	block := &bc.Block{
		BlockHeader: &bc.BlockHeader{Version: 1},
	}

	for i, c := range cases {
		parent.Timestamp = c.parentTime[0]
		parentSuccessor := parent
		for i := 1; i < len(c.parentTime); i++ {
			Previous := &types.BlockHeader{Version: 1, Timestamp: c.parentTime[i]}
			parentSuccessor.PreviousBlockHash = Previous.Hash()
			parentSuccessor = Previous
		}

		block.Timestamp = c.blockTime
		if err := checkBlockTime(block, parent); rootErr(err) != c.err {
			t.Errorf("case %d got error %s, want %s", i, err, c.err)
		}
	}
}

func TestCheckCoinbaseAmount(t *testing.T) {
	cases := []struct {
		block      *types.Block
		checkpoint *state.Checkpoint
		err        error
	}{
		{
			block: &types.Block{
				BlockHeader: types.BlockHeader{Height: 0},
				Transactions: []*types.Tx{
					types.NewTx(types.TxData{
						Inputs: []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs: []*types.TxOutput{
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 0, []byte("controlProgram"), nil),
						},
					}),
				},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{hex.EncodeToString([]byte("controlProgram")): 5000},
			},
			err: nil,
		},
		{
			block: &types.Block{
				BlockHeader: types.BlockHeader{Height: state.BlocksOfEpoch + 1},
				Transactions: []*types.Tx{
					types.NewTx(types.TxData{
						Inputs: []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs: []*types.TxOutput{
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 0, []byte("controlProgram"), nil),
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 5000, []byte("controlProgram"), nil),
						},
					}),
				},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{hex.EncodeToString([]byte("controlProgram")): 5000},
			},
			err: nil,
		},
		{
			block: &types.Block{
				BlockHeader: types.BlockHeader{Height: state.BlocksOfEpoch + 1},
				Transactions: []*types.Tx{
					types.NewTx(types.TxData{
						Inputs: []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs: []*types.TxOutput{
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 0, []byte("controlProgram"), nil),
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 5000, []byte("controlProgram1"), nil),
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 5000, []byte("controlProgram2"), nil),
						},
					}),
				},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{
					hex.EncodeToString([]byte("controlProgram1")): 5000,
					hex.EncodeToString([]byte("controlProgram2")): 5000},
			},
			err: nil,
		},
		{
			block: &types.Block{
				BlockHeader:  types.BlockHeader{},
				Transactions: []*types.Tx{},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{"controlProgram": 5000},
			},
			err: ErrWrongCoinbaseTransaction,
		},
	}

	for i, c := range cases {
		if err := checkCoinbaseAmount(types.MapBlock(c.block), c.checkpoint); rootErr(err) != c.err {
			t.Errorf("case %d got error %v, want %v", i, err, c.err)
		}
	}
}

func TestValidateBlockHeader(t *testing.T) {
	cases := []struct {
		desc   string
		block  *bc.Block
		parent *state.BlockNode
		err    error
	}{
		{
			block: &bc.Block{BlockHeader: &bc.BlockHeader{
				Version: 2,
			}},
			parent: &state.BlockNode{
				Version: 1,
			},
			err: errVersionRegression,
		},
		{
			block: &bc.Block{BlockHeader: &bc.BlockHeader{
				Version: 1,
				Height:  20,
			}},
			parent: &state.BlockNode{
				Version: 1,
				Height:  18,
			},
			err: errMisorderedBlockHeight,
		},
		{
			desc: "the prev block hash not equals to the hash of parent (blocktest#1004)",
			block: &bc.Block{BlockHeader: &bc.BlockHeader{
				Version:         1,
				Height:          20,
				PreviousBlockId: &bc.Hash{V0: 18},
			}},
			parent: &state.BlockNode{
				Version: 1,
				Height:  19,
				Hash:    bc.Hash{V0: 19},
			},
			err: errMismatchedBlock,
		},
		{
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version:         1,
					Height:          1,
					Timestamp:       1523358600,
					PreviousBlockId: &bc.Hash{V0: 0},
				},
			},
			parent: &state.BlockNode{
				Version:   1,
				Height:    0,
				Timestamp: 1523352600,
				Hash:      bc.Hash{V0: 0},
			},
			err: nil,
		},
		{
			desc: "version greater than 1 (blocktest#1001)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version: 2,
				},
			},
			parent: &state.BlockNode{
				Version: 1,
			},
			err: errVersionRegression,
		},
		{
			desc: "version equals 0 (blocktest#1002)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version: 0,
				},
			},
			parent: &state.BlockNode{
				Version: 1,
			},
			err: errVersionRegression,
		},
		{
			desc: "version equals max uint64 (blocktest#1003)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version: math.MaxUint64,
				},
			},
			parent: &state.BlockNode{
				Version: 1,
			},
			err: errVersionRegression,
		},
	}

	for i, c := range cases {
		if err := ValidateBlockHeader(c.block, c.parent); rootErr(err) != c.err {
			t.Errorf("case %d (%s) got error %s, want %s", i, c.desc, err, c.err)
		}
	}
}

// TestValidateBlock test the ValidateBlock function
func TestValidateBlock(t *testing.T) {
	cp, _ := vmutil.DefaultCoinbaseProgram()
	converter := func(prog []byte) ([]byte, error) { return nil, nil }
	cases := []struct {
		desc       string
		block      *bc.Block
		parent     *state.BlockNode
		checkpoint *state.Checkpoint
		err        error
	}{
		{
			desc: "The calculated transaction merkel root hash is not equals to the hash of the block header (blocktest#1009)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version:          1,
					Height:           1,
					Timestamp:        1523358600,
					PreviousBlockId:  &bc.Hash{V0: 0},
					TransactionsRoot: &bc.Hash{V0: 1},
				},
				Transactions: []*bc.Tx{
					types.MapTx(&types.TxData{
						Version:        1,
						SerializedSize: 1,
						Inputs:         []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs: []*types.TxOutput{
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 0, cp, nil),
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 41250000000, cp, nil),
						},
					}),
				},
			},
			parent: &state.BlockNode{
				Version:   1,
				Height:    0,
				Timestamp: 1523352600,
				Hash:      bc.Hash{V0: 0},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{hex.EncodeToString(cp): 41250000000}},
			err: errMismatchedMerkleRoot,
		},
		{
			desc: "The calculated transaction status merkel root hash is not equals to the hash of the block header (blocktest#1009)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version:          1,
					Height:           1,
					Timestamp:        1523358600,
					PreviousBlockId:  &bc.Hash{V0: 0},
					TransactionsRoot: &bc.Hash{V0: 6294987741126419124, V1: 12520373106916389157, V2: 5040806596198303681, V3: 1151748423853876189},
				},
				Transactions: []*bc.Tx{
					types.MapTx(&types.TxData{
						Version:        1,
						SerializedSize: 1,
						Inputs:         []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs: []*types.TxOutput{
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 0, cp, nil),
							types.NewOriginalTxOutput(*consensus.BTMAssetID, 41250000000, cp, nil),
						},
					}),
				},
			},
			parent: &state.BlockNode{
				Version:   1,
				Height:    0,
				Timestamp: 1523352600,
				Hash:      bc.Hash{V0: 0},
			},
			checkpoint: &state.Checkpoint{
				Rewards: map[string]uint64{hex.EncodeToString(cp): 41250000000},
			},
			err: errMismatchedMerkleRoot,
		},
		{
			desc: "the coinbase amount is less than the real coinbase amount (txtest#1014)",
			block: &bc.Block{
				ID: bc.Hash{V0: 1},
				BlockHeader: &bc.BlockHeader{
					Version:         1,
					Height:          1,
					Timestamp:       1523358600,
					PreviousBlockId: &bc.Hash{V0: 0},
				},
				Transactions: []*bc.Tx{
					types.MapTx(&types.TxData{
						Version:        1,
						SerializedSize: 1,
						Inputs:         []*types.TxInput{types.NewCoinbaseInput(nil)},
						Outputs:        []*types.TxOutput{types.NewOriginalTxOutput(*consensus.BTMAssetID, 41250000000, cp, nil)},
					}),
					types.MapTx(&types.TxData{
						Version:        1,
						SerializedSize: 1,
						Inputs:         []*types.TxInput{types.NewSpendInput([][]byte{}, *newHash(8), *consensus.BTMAssetID, 100000000, 0, cp, nil)},
						Outputs:        []*types.TxOutput{types.NewOriginalTxOutput(*consensus.BTMAssetID, 90000000, cp, nil)},
					}),
				},
			},
			parent: &state.BlockNode{
				Version:   1,
				Height:    0,
				Timestamp: 1523352600,
				Hash:      bc.Hash{V0: 0},
			},
			checkpoint: &state.Checkpoint{},
			err:        ErrWrongCoinbaseTransaction,
		},
	}

	for i, c := range cases {
		err := ValidateBlock(c.block, c.parent, c.checkpoint, converter)
		if rootErr(err) != c.err {
			t.Errorf("case #%d (%s) got error %s, want %s", i, c.desc, err, c.err)
		}
	}
}

// TestGasOverBlockLimit check if the gas of the block has the max limit (blocktest#1012)
func TestGasOverBlockLimit(t *testing.T) {
	cp, _ := vmutil.DefaultCoinbaseProgram()
	converter := func(prog []byte) ([]byte, error) { return nil, nil }
	parent := &state.BlockNode{
		Version:   1,
		Height:    0,
		Timestamp: 1523352600,
		Hash:      bc.Hash{V0: 0},
	}
	block := &bc.Block{
		ID: bc.Hash{V0: 1},
		BlockHeader: &bc.BlockHeader{
			Version:          1,
			Height:           1,
			Timestamp:        1523358600,
			PreviousBlockId:  &bc.Hash{V0: 0},
			TransactionsRoot: &bc.Hash{V0: 1},
		},
		Transactions: []*bc.Tx{
			types.MapTx(&types.TxData{
				Version:        1,
				SerializedSize: 1,
				Inputs:         []*types.TxInput{types.NewCoinbaseInput(nil)},
				Outputs:        []*types.TxOutput{types.NewOriginalTxOutput(*consensus.BTMAssetID, 41250000000, cp, nil)},
			}),
		},
	}

	checkpoint := &state.Checkpoint{
		Rewards: nil,
	}

	for i := 0; i < 100; i++ {
		block.Transactions = append(block.Transactions, types.MapTx(&types.TxData{
			Version:        1,
			SerializedSize: 100000,
			Inputs: []*types.TxInput{
				types.NewSpendInput([][]byte{}, *newHash(8), *consensus.BTMAssetID, 10000000000, 0, cp, nil),
			},
			Outputs: []*types.TxOutput{
				types.NewOriginalTxOutput(*consensus.BTMAssetID, 9000000000, cp, nil),
			},
		}))
	}

	if err := ValidateBlock(block, parent, checkpoint, converter); err != errOverBlockLimit {
		t.Errorf("got error %s, want %s", err, errOverBlockLimit)
	}
}
