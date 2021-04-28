package protocol

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/bytom/bytom/config"
	"github.com/bytom/bytom/event"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
	"github.com/bytom/bytom/protocol/state"
)

const maxProcessBlockChSize = 1024

// Chain provides functions for working with the Bytom block chain.
type Chain struct {
	index           *state.BlockIndex
	orphanManage    *OrphanManage
	txPool          *TxPool
	store           Store
	processBlockCh  chan *processBlockMsg
	rollbackBlockCh chan bc.Hash
	casper          CasperConsensus
	eventDispatcher *event.Dispatcher

	cond     sync.Cond
	bestNode *state.BlockNode
}

// NewChain returns a new Chain using store as the underlying storage.
func NewChain(store Store, txPool *TxPool) (*Chain, error) {
	return NewChainWithOrphanManage(store, txPool, NewOrphanManage())
}

func NewChainWithOrphanManage(store Store, txPool *TxPool, manage *OrphanManage) (*Chain, error) {
	c := &Chain{
		orphanManage:   manage,
		txPool:         txPool,
		store:          store,
		processBlockCh: make(chan *processBlockMsg, maxProcessBlockChSize),
	}
	c.cond.L = new(sync.Mutex)

	storeStatus := store.GetStoreStatus()
	if storeStatus == nil {
		if err := c.initChainStatus(); err != nil {
			return nil, err
		}
		storeStatus = store.GetStoreStatus()
	}

	var err error
	if c.index, err = store.LoadBlockIndex(storeStatus.Height); err != nil {
		return nil, err
	}

	c.bestNode = c.index.GetNode(storeStatus.Hash)
	c.index.SetMainChain(c.bestNode)
	go c.blockProcesser()
	return c, nil
}

func (c *Chain) initChainStatus() error {
	genesisBlock := config.GenesisBlock()
	if err := c.store.SaveBlock(genesisBlock); err != nil {
		return err
	}

	utxoView := state.NewUtxoViewpoint()
	bcBlock := types.MapBlock(genesisBlock)
	if err := utxoView.ApplyBlock(bcBlock); err != nil {
		return err
	}

	node, err := state.NewBlockNode(&genesisBlock.BlockHeader, nil)
	if err != nil {
		return err
	}

	contractView := state.NewContractViewpoint()
	return c.store.SaveChainStatus(node, utxoView, contractView)
}

// BestBlockHeight returns the last irreversible block header of the blockchain
func (c *Chain) LastIrreversibleHeader() *types.BlockHeader {
	_, hash := c.casper.LastFinalized()
	node := c.index.GetNode(&hash)
	return node.BlockHeader()
}

// ProcessBlockVerification process block verification
func (c *Chain) ProcessBlockVerification(v *Verification) error {
	return c.casper.AuthVerification(v)
}

// BestBlockHeight returns the current height of the blockchain.
func (c *Chain) BestBlockHeight() uint64 {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()
	return c.bestNode.Height
}

// BestBlockHash return the hash of the chain tail block
func (c *Chain) BestBlockHash() *bc.Hash {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()
	return &c.bestNode.Hash
}

// BestBlockHeader returns the chain tail block
func (c *Chain) BestBlockHeader() *types.BlockHeader {
	node := c.index.BestNode()
	return node.BlockHeader()
}

// InMainChain checks wheather a block is in the main chain
func (c *Chain) InMainChain(hash bc.Hash) bool {
	return c.index.InMainchain(hash)
}

func (c *Chain) GetBlockIndex() *state.BlockIndex {
	return c.index
}

func (c *Chain) SignBlockHeader(blockHeader *types.BlockHeader) {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()
	xprv := config.CommonConfig.PrivateKey()
	signature := xprv.Sign(blockHeader.Hash().Bytes())
	blockHeader.Set(signature)
}

// This function must be called with mu lock in above level
func (c *Chain) setState(node *state.BlockNode, view *state.UtxoViewpoint, contractView *state.ContractViewpoint) error {
	if err := c.store.SaveChainStatus(node, view, contractView); err != nil {
		return err
	}

	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	c.index.SetMainChain(node)
	c.bestNode = node

	log.WithFields(log.Fields{"module": logModule, "height": c.bestNode.Height, "hash": c.bestNode.Hash.String()}).Debug("chain best status has been update")
	c.cond.Broadcast()
	return nil
}

// BlockWaiter returns a channel that waits for the block at the given height.
func (c *Chain) BlockWaiter(height uint64) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		c.cond.L.Lock()
		defer c.cond.L.Unlock()
		for c.bestNode.Height < height {
			c.cond.Wait()
		}
		ch <- struct{}{}
	}()

	return ch
}

// GetTxPool return chain txpool.
func (c *Chain) GetTxPool() *TxPool {
	return c.txPool
}
