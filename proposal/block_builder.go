package proposal

import (
	"sort"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bytom/bytom/account"
	"github.com/bytom/bytom/blockchain/txbuilder"
	consensusConfig "github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/protocol"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
	"github.com/bytom/bytom/protocol/consensus"
	"github.com/bytom/bytom/protocol/state"
	"github.com/bytom/bytom/protocol/validation"
	"github.com/bytom/bytom/protocol/vm/vmutil"
)

const logModule = "proposal"

type BlockBuilder struct {
	chain          *protocol.Chain
	casper         *consensus.Casper
	accountManager *account.Manager
}

func (bd *BlockBuilder) Build(timeStamp uint64) (*types.Block, error) {
	preHeight, preHash := bd.casper.BestChain()
	block := &types.Block{
		BlockHeader: types.BlockHeader{
			Version:           1,
			Height:            preHeight + 1,
			PreviousBlockHash: preHash,
			Timestamp:         timeStamp,
			BlockCommitment:   types.BlockCommitment{},
		},
		// leave the first transaction for coinbase transaction
		Transactions: []*types.Tx{nil},
	}

	txStatus, err := bd.applyTransactions(block)
	if err != nil {
		return nil, err
	}
	err = bd.finalize(block, txStatus)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (bd *BlockBuilder) applyTransactions(block *types.Block) (txStatus *bc.TransactionStatus, err error) {
	bcBlock := &bc.Block{BlockHeader: &bc.BlockHeader{Height: block.Height}}

	view := state.NewUtxoViewpoint()
	txStatus = bc.NewTransactionStatus()
	if err := txStatus.SetStatus(0, false); err != nil {
		return
	}
	gasUsed := uint64(0)
	txFee := uint64(0)

	txPool := bd.chain.GetTxPool()
	txs := txPool.GetTransactions()
	sort.Sort(byTime(txs))
	for _, txDesc := range txs {
		tx := txDesc.Tx.Tx
		gasOnlyTx := false

		if err := bd.chain.GetTransactionsUtxo(view, []*bc.Tx{tx}); err != nil {
			removeTransactionForError(txPool, &tx.ID, err)
			continue
		}

		gasStatus, err := validation.ValidateTx(tx, bcBlock)
		if err != nil {
			if !gasStatus.GasValid {
				removeTransactionForError(txPool, &tx.ID, err)
				continue
			}
			gasOnlyTx = true
		}

		if gasUsed+uint64(gasStatus.GasUsed) > consensusConfig.MaxBlockGas {
			break
		}

		if err := view.ApplyTransaction(bcBlock, tx, gasOnlyTx); err != nil {
			removeTransactionForError(txPool, &tx.ID, err)
			continue
		}

		if err := txStatus.SetStatus(len(block.Transactions), gasOnlyTx); err != nil {
			return nil, err
		}

		block.Transactions = append(block.Transactions, txDesc.Tx)
		gasUsed += uint64(gasStatus.GasUsed)
		txFee += txDesc.Fee
	}

	// create coinbase transaction
	block.Transactions[0], err = createCoinbaseTx(bd.accountManager, txFee, block.Height)
	if err != nil {
		return nil, errors.Wrap(err, "fail on createCoinbaseTx")
	}
	return
}

func (bd *BlockBuilder) finalize(block *types.Block, txStatus *bc.TransactionStatus) error {
	var err error
	var txEntries []*bc.Tx
	for _, tx := range block.Transactions {
		txEntries = append(txEntries, tx.Tx)
	}
	block.BlockHeader.BlockCommitment.TransactionsMerkleRoot, err = types.TxMerkleRoot(txEntries)
	if err != nil {
		return err
	}

	block.BlockHeader.BlockCommitment.TransactionStatusHash, err = types.TxStatusMerkleRoot(txStatus.VerifyStatus)
	return err
}

func removeTransactionForError(txPool *protocol.TxPool, txHash *bc.Hash, err error) {
	log.WithFields(log.Fields{"module": logModule, "error": err}).Error("mining block generation: skip tx due to")
	txPool.RemoveTransaction(txHash)
}

func createCoinbaseTx(accountManager *account.Manager, amount uint64, blockHeight uint64) (tx *types.Tx, err error) {
	amount += consensusConfig.BlockSubsidy(blockHeight)
	arbitrary := append([]byte{0x00}, []byte(strconv.FormatUint(blockHeight, 10))...)

	var script []byte
	if accountManager == nil {
		script, err = vmutil.DefaultCoinbaseProgram()
	} else {
		script, err = accountManager.GetCoinbaseControlProgram()
		arbitrary = append(arbitrary, accountManager.GetCoinbaseArbitrary()...)
	}
	if err != nil {
		return nil, err
	}

	if len(arbitrary) > consensusConfig.CoinbaseArbitrarySizeLimit {
		return nil, validation.ErrCoinbaseArbitraryOversize
	}

	builder := txbuilder.NewBuilder(time.Now())
	if err = builder.AddInput(types.NewCoinbaseInput(arbitrary), &txbuilder.SigningInstruction{}); err != nil {
		return nil, err
	}
	if err = builder.AddOutput(types.NewTxOutput(*consensusConfig.BTMAssetID, amount, script)); err != nil {
		return nil, err
	}
	_, txData, err := builder.Build()
	if err != nil {
		return nil, err
	}

	byteData, err := txData.MarshalText()
	if err != nil {
		return nil, err
	}
	txData.SerializedSize = uint64(len(byteData))

	tx = &types.Tx{
		TxData: *txData,
		Tx:     types.MapTx(txData),
	}
	return tx, nil
}