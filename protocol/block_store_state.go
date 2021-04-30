package protocol

import (
	"encoding/hex"
	"fmt"

	"github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/math/checked"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
)

type RewardAndProgram struct {
	Reward         uint64
	ControlProgram []byte
}

// BlockStoreState represents the core's db status
type BlockStoreState struct {
	Height uint64
	Hash   *bc.Hash

	// the reward statistics of validator
	//   key: control program who gets the reward
	//	 value: reward amount
	Rewards map[string]uint64
}

func NewBlockStoreState(height uint64, hash *bc.Hash) *BlockStoreState {
	return &BlockStoreState{
		Height:  height,
		Hash:    hash,
		Rewards: map[string]uint64{},
	}
}

// ApplyBlock calculate a new block reward for reward statistics
func (rs *BlockStoreState) ApplyBlock(block *types.Block, validatorPledge uint64) error {
	if block.PreviousBlockHash != *rs.Hash {
		panic("block previous hash is not equal to BlockStoreState hash")
	}

	if err := rs.calculateReward(block, true); err != nil {
		return err
	}

	rs.Height++
	hash := block.Hash()
	rs.Hash = &hash
	return nil
}

func (rs *BlockStoreState) calculateReward(block *types.Block, isAdd bool) error {
	blockReward, err := calculateReward(block)
	if err != nil {
		return err
	}

	hexControlProgram := hex.EncodeToString(blockReward.ControlProgram)
	if isAdd {
		rs.Rewards[hexControlProgram] += blockReward.Reward
	} else {
		rs.Rewards[hexControlProgram] -= blockReward.Reward
		if rs.Rewards[hexControlProgram] == 0 {
			delete(rs.Rewards, hexControlProgram)
		}
	}

	return nil
}

// DetachBlock delete a block reward from reward statistics
func (rs *BlockStoreState) DetachBlock(block *types.Block, validatorPledge uint64) error {
	if block.Hash() != *rs.Hash {
		hash := block.Hash()
		panic(fmt.Sprintf("the block %s is not exist in BlockStoreState", (&hash).String()))
	}

	if err := rs.calculateReward(block, false); err != nil {
		return err
	}

	rs.Height--
	hash := block.PreviousBlockHash
	rs.Hash = &hash
	return nil
}

// GetRewards return a list Rewards for creating coinbase transaction.
func (rs *BlockStoreState) GetRewards() (rewards []RewardAndProgram) {
	for hexProgram, rewardAmount := range rs.Rewards {
		program, _ := hex.DecodeString(hexProgram)
		rewards = append(rewards, RewardAndProgram{
			Reward:         rewardAmount,
			ControlProgram: program,
		})
	}

	return
}

// calculateReward calculate block subsidy and transaction fee
func calculateReward(block *types.Block) (RewardAndProgram, error) {
	var rp RewardAndProgram

	rp.ControlProgram = block.Transactions[0].Outputs[0].ControlProgram
	rp.Reward = consensus.BlockSubsidy(block.Height)
	for _, tx := range block.Transactions {
		if fee, err := calculateFee(tx); err != nil {
			return rp, errors.Wrap(checked.ErrOverflow, "calculate transaction fee")
		} else {
			rp.Reward += fee
		}
	}

	return rp, nil
}

// calculateFee calculate the fee of a transaction
func calculateFee(tx *types.Tx) (uint64, error) {
	var fee uint64
	var ok bool
	for _, input := range tx.Inputs {
		// coinbase transaction fee free
		if input.TypedInput.InputType() == types.CoinbaseInputType {
			return 0, nil
		}

		if input.AssetID() != *consensus.BTMAssetID {
			continue
		}

		if fee, ok = checked.AddUint64(input.Amount(), fee); !ok {
			return 0, checked.ErrOverflow
		}
	}

	for _, output := range tx.Outputs {
		if *output.AssetAmount.AssetId != *consensus.BTMAssetID {
			continue
		}

		if fee, ok = checked.SubUint64(fee, output.Amount); !ok {
			return 0, checked.ErrOverflow
		}
	}

	return fee, nil
}
