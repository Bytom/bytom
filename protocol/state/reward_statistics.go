package state

import (
	"encoding/hex"
	"fmt"

	"github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/math/checked"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
)

// RewardAndProgram a reward record
// 		reward: reward amount for every 100 blocks
//		controlProgram: who gets the reward
type RewardAndProgram struct {
	reward         uint64
	controlProgram []byte
}

// RewardStatistics represents reward statistics every 100 blocks
type RewardStatistics struct {
	rewards     map[string]uint64
	BlockHash   bc.Hash
	BlockHeight uint64
}

func NewRewardStatistics(blockHash bc.Hash, BlockHeight uint64) *RewardStatistics {
	return &RewardStatistics{
		rewards:     map[string]uint64{},
		BlockHash:   blockHash,
		BlockHeight: BlockHeight,
	}
}

// ApplyBlock calculate a new block reward for reward statistics
func (rs *RewardStatistics) ApplyBlock(block *types.Block) error {
	if block.PreviousBlockHash != rs.BlockHash {
		return errors.New("block previous hash is not equal to reward hash")
	}

	if block.Height%BlocksOfEpoch == 1 {
		rs.rewards = map[string]uint64{}
	}

	if err := rs.calculateReward(block, true); err != nil {
		return err
	}

	rs.BlockHash = block.Hash()
	rs.BlockHeight++
	return nil
}

func (rs *RewardStatistics) calculateReward(block *types.Block, isAdd bool) error {
	blockReward, err := calculateReward(block)
	if err != nil {
		return err
	}

	hexControlProgram := hex.EncodeToString(blockReward.controlProgram)
	if isAdd {
		rs.rewards[hexControlProgram] += blockReward.reward
	} else {
		rs.rewards[hexControlProgram] -= blockReward.reward
		if rs.rewards[hexControlProgram] == 0 {
			delete(rs.rewards, hexControlProgram)
		}
	}

	return nil
}

// DetachBlock delete a block reward from reward statistics
func (rs *RewardStatistics) DetachBlock(block *types.Block) error {
	if block.Hash() != rs.BlockHash {
		hash := block.Hash()
		return errors.New(fmt.Sprintf("the block %s is not exist in reward", (&hash).String()))
	}

	if err := rs.calculateReward(block, false); err != nil {
		return err
	}

	rs.BlockHash = block.PreviousBlockHash
	rs.BlockHeight--
	return nil
}

// GetRewards return a list rewards for creating coinbase transaction.
func (rs *RewardStatistics) GetRewards() (rewards []RewardAndProgram) {
	for hexProgram, rewardAmount := range rs.rewards {
		program, _ := hex.DecodeString(hexProgram)
		rewards = append(rewards, RewardAndProgram{
			reward:         rewardAmount,
			controlProgram: program,
		})
	}

	return
}

// calculateReward calculate block subsidy and transaction fee
func calculateReward(block *types.Block) (RewardAndProgram, error) {
	var rp RewardAndProgram

	rp.controlProgram = block.Transactions[0].Outputs[0].ControlProgram
	rp.reward = consensus.BlockSubsidy(block.Height, 100)
	for _, tx := range block.Transactions {
		if fee, err := calculateFee(tx); err != nil {
			return rp, errors.Wrap(checked.ErrOverflow, "calculate transaction fee")
		} else {
			rp.reward += fee
		}
	}

	return rp, nil
}

// calculateFee calculate the fee of a transaction
func calculateFee(tx *types.Tx) (uint64, error) {
	var fee uint64
	var ok bool
	for _, input := range tx.Inputs {
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
