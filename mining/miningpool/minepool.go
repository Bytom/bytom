package miningpool

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bytom/account"
	"github.com/bytom/mining"
	"github.com/bytom/protocol"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
)

const (
	blockUpdateMS   = 1000
	maxSubmitChSize = 50
)

type submitBlockMsg struct {
	blockHeader *types.BlockHeader
	reply       chan error
}

// MiningPool is the support struct for p2p mine pool
type MiningPool struct {
	mutex    sync.RWMutex
	block    *types.Block
	submitCh chan *submitBlockMsg

	chain          *protocol.Chain
	accountManager *account.Manager
	txPool         *protocol.TxPool
	newBlockCh     chan *bc.Hash
}

// NewMiningPool will create a new MiningPool
func NewMiningPool(c *protocol.Chain, accountManager *account.Manager, txPool *protocol.TxPool, newBlockCh chan *bc.Hash) *MiningPool {
	m := &MiningPool{
		submitCh:       make(chan *submitBlockMsg, maxSubmitChSize),
		chain:          c,
		accountManager: accountManager,
		txPool:         txPool,
		newBlockCh:     newBlockCh,
	}
	go m.blockUpdater()
	return m
}

// blockUpdater is the goroutine for keep update mining block
func (m *MiningPool) blockUpdater() {
	ticker := time.NewTicker(time.Millisecond * blockUpdateMS)
	for {
		select {
		case <-ticker.C:
			m.generateBlock()

		case submitMsg := <-m.submitCh:
			err := m.submitWork(submitMsg.blockHeader)
			if err == nil {
				m.generateBlock()
			}
			submitMsg.reply <- err
		}
	}
}

func (m *MiningPool) RenewBlkTplWithArbitrary(coinbaseAb []byte) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.block != nil {
		abUsing := m.block.CoinbaseArbitrary()
		abToUse := append([]byte{0x00}, []byte(strconv.FormatUint(m.block.BlockHeader.Height, 10))...)
		abToUse = append(abToUse, coinbaseAb...)

		log.Info(abUsing)
		log.Info(abToUse)
		if bytes.Equal(abUsing, abToUse) {
			log.Info("equal")
			return
		}
	}

	log.Info("not equal")

	block, err := mining.NewBlockTemplate(m.chain, m.txPool, m.accountManager, coinbaseAb)
	if err != nil {
		log.Errorf("miningpool: failed on create NewBlockTemplate: %v", err)
		return
	}

	m.block = block
}

// generateBlock generates a block template to mine
func (m *MiningPool) generateBlock() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.block != nil && *m.chain.BestBlockHash() == m.block.PreviousBlockHash {
		m.block.Timestamp = uint64(time.Now().Unix())
		return
	}

	block, err := mining.NewBlockTemplate(m.chain, m.txPool, m.accountManager, []byte{})
	if err != nil {
		log.Errorf("miningpool: failed on create NewBlockTemplate: %v", err)
		return
	}

	m.block = block
}

// GetWork will return a block header for p2p mining
func (m *MiningPool) GetWork() (*types.BlockHeader, *types.Block, error) {
	if m.block != nil {
		m.mutex.RLock()
		defer m.mutex.RUnlock()
		bh := m.block.BlockHeader
		return &bh, m.block, nil
	}
	return nil, nil, errors.New("no block is ready for mining")
}

// SubmitWork will try to submit the result to the blockchain
func (m *MiningPool) SubmitWork(bh *types.BlockHeader) error {
	reply := make(chan error, 1)
	m.submitCh <- &submitBlockMsg{blockHeader: bh, reply: reply}
	err := <-reply
	if err != nil {
		log.WithFields(log.Fields{"err": err, "height": bh.Height}).Warning("submitWork failed")
	}
	return err
}

func (m *MiningPool) submitWork(bh *types.BlockHeader) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.block == nil || bh.PreviousBlockHash != m.block.PreviousBlockHash {
		return errors.New("pending mining block has been changed")
	}

	m.block.Nonce = bh.Nonce
	m.block.Timestamp = bh.Timestamp
	isOrphan, err := m.chain.ProcessBlock(m.block)
	if err != nil {
		return err
	}
	if isOrphan {
		return errors.New("submit result is orphan")
	}

	blockHash := bh.Hash()
	m.newBlockCh <- &blockHash
	return nil
}
