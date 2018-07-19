package netsync

import (
	"encoding/hex"
	"net"
	"path"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tendermint/go-crypto"
	cmn "github.com/tendermint/tmlibs/common"

	cfg "github.com/bytom/config"
	"github.com/bytom/consensus"
	"github.com/bytom/p2p"
	"github.com/bytom/p2p/discover"
	"github.com/bytom/p2p/pex"
	core "github.com/bytom/protocol"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
	"github.com/bytom/version"
)

const (
	maxTxChanSize = 10000
)

//SyncManager Sync Manager is responsible for the business layer information synchronization
type SyncManager struct {
	sw          *p2p.Switch
	genesisHash bc.Hash

	privKey      crypto.PrivKeyEd25519 // local node's p2p key
	chain        *core.Chain
	txPool       *core.TxPool
	blockFetcher *blockFetcher
	blockKeeper  *blockKeeper
	peers        *peerSet

	newTxCh    chan *types.Tx
	newBlockCh chan *bc.Hash
	txSyncCh   chan *txSyncMsg
	quitSync   chan struct{}
	config     *cfg.Config
}

//NewSyncManager create a sync manager
func NewSyncManager(config *cfg.Config, chain *core.Chain, txPool *core.TxPool, newBlockCh chan *bc.Hash) (*SyncManager, error) {
	genesisHeader, err := chain.GetHeaderByHeight(0)
	if err != nil {
		return nil, err
	}

	sw := p2p.NewSwitch(config)
	peers := newPeerSet(sw)
	manager := &SyncManager{
		sw:           sw,
		genesisHash:  genesisHeader.Hash(),
		txPool:       txPool,
		chain:        chain,
		privKey:      crypto.GenPrivKeyEd25519(),
		blockFetcher: newBlockFetcher(chain, peers),
		blockKeeper:  newBlockKeeper(chain, peers),
		peers:        peers,
		newTxCh:      make(chan *types.Tx, maxTxChanSize),
		newBlockCh:   newBlockCh,
		txSyncCh:     make(chan *txSyncMsg),
		quitSync:     make(chan struct{}),
		config:       config,
	}

	protocolReactor := NewProtocolReactor(manager, manager.peers)
	manager.sw.AddReactor("PROTOCOL", protocolReactor)

	// Create & add listener
	var listenerStatus bool
	var l p2p.Listener
	if !config.VaultMode {
		p, address := protocolAndAddress(manager.config.P2P.ListenAddress)
		l, listenerStatus = p2p.NewDefaultListener(p, address, manager.config.P2P.SkipUPNP)
		manager.sw.AddListener(l)

		discv, err := initDiscover(config, &manager.privKey, l.ExternalAddress().Port)
		if err != nil {
			return nil, err
		}

		pexReactor := pex.NewPEXReactor(discv)
		manager.sw.AddReactor("PEX", pexReactor)
	}
	manager.sw.SetNodeInfo(manager.makeNodeInfo(listenerStatus))
	manager.sw.SetNodePrivKey(manager.privKey)
	return manager, nil
}

func (sm *SyncManager) IsCaughtUp() bool {
	peer := sm.peers.BestPeer(consensus.SFFullNode)
	return peer == nil || peer.Height() <= sm.chain.BestBlockHeight()
}

func (sm *SyncManager) handleBlockMsg(peer *peer, msg *BlockMessage) {
	sm.blockKeeper.processBlock(peer.ID(), msg.GetBlock())
}

func (sm *SyncManager) handleBlocksMsg(peer *peer, msg *BlocksMessage) {
	blocks, err := msg.GetBlocks()
	if err != nil {
		return
	}

	sm.blockKeeper.processBlocks(peer.ID(), blocks)
}

func (sm *SyncManager) handleGetBlockMsg(peer *peer, msg *GetBlockMessage) {
	var block *types.Block
	var err error
	if msg.Height != 0 {
		block, err = sm.chain.GetBlockByHeight(msg.Height)
	} else {
		block, err = sm.chain.GetBlockByHash(msg.GetHash())
	}
	if err != nil {
		log.WithField("err", err).Warning("fail on handleGetBlockMsg get block from chain")
		return
	}

	if err := peer.sendBlock(block); err != nil {
		log.WithField("err", err).Warning("fail on handleGetBlockMsg sentBlock")
	}
}

func (sm *SyncManager) handleGetBlocksMsg(peer *peer, msg *GetBlocksMessage) {
	blocks, err := sm.blockKeeper.locateBlocks(msg.GetBlockLocator(), msg.GetStopHash())
	if err != nil || len(blocks) == 0 {
		return
	}

	peer.sendBlocks(blocks)
}

func (sm *SyncManager) handleGetHeadersMsg(peer *peer, msg *GetHeadersMessage) {
	headers, err := sm.blockKeeper.locateHeaders(msg.GetBlockLocator(), msg.GetStopHash())
	if err != nil || len(headers) == 0 {
		return
	}

	peer.sendHeaders(headers)
}

func (sm *SyncManager) handleHeadersMsg(peer *peer, msg *HeadersMessage) {
	headers, err := msg.GetHeaders()
	if err != nil {
		return
	}

	sm.blockKeeper.processHeaders(peer.ID(), headers)
}

func (sm *SyncManager) handleMineBlockMsg(peer *peer, msg *MineBlockMessage) {
	block, err := msg.GetMineBlock()
	if err != nil {
		log.WithField("err", err).Warning("fail on handleMineBlockMsg GetMineBlock")
		return
	}

	hash := block.Hash()
	peer.markBlock(&hash)
	sm.blockFetcher.processNewBlock(&blockMsg{peerID: peer.ID(), block: block})
	peer.setStatus(block.Height, &hash)
}

func (sm *SyncManager) handleStatusRequestMsg(peer *peer) {
	bestHeader := sm.chain.BestBlockHeader()
	genesisBlock, err := sm.chain.GetBlockByHeight(0)
	if err != nil {
		log.WithField("err", err).Error("fail on handleStatusRequestMsg get genesis")
	}

	genesisHash := genesisBlock.Hash()
	peer.sendStatus(bestHeader, &genesisHash)
}

func (sm *SyncManager) handleStatusResponseMsg(basePeer BasePeer, msg *StatusResponseMessage) {
	if peer := sm.peers.getPeer(basePeer.ID()); peer != nil {
		peer.setStatus(msg.Height, msg.GetHash())
		return
	}

	if genesisHash := msg.GetGenesisHash(); sm.genesisHash != *genesisHash {
		log.WithFields(log.Fields{
			"remote genesis": genesisHash.String(),
			"local genesis":  sm.genesisHash.String(),
		}).Warn("fail hand shake due to differnt genesis")
		return
	}

	sm.peers.addPeer(basePeer, msg.Height, msg.GetHash())
}

func (sm *SyncManager) handleTransactionMsg(peer *peer, msg *TransactionMessage) {
	tx, err := msg.GetTransaction()
	if err != nil {
		sm.peers.addBanScore(peer.ID(), 0, 10, "fail on get tx from message")
		return
	}

	if isOrphan, err := sm.chain.ValidateTx(tx); err != nil && isOrphan == false {
		sm.peers.addBanScore(peer.ID(), 10, 0, "fail on validate tx transaction")
	}
}

// Defaults to tcp
func protocolAndAddress(listenAddr string) (string, string) {
	p, address := "tcp", listenAddr
	parts := strings.SplitN(address, "://", 2)
	if len(parts) == 2 {
		p, address = parts[0], parts[1]
	}
	return p, address
}

func (sm *SyncManager) makeNodeInfo(listenerStatus bool) *p2p.NodeInfo {
	nodeInfo := &p2p.NodeInfo{
		PubKey:  sm.privKey.PubKey().Unwrap().(crypto.PubKeyEd25519),
		Moniker: sm.config.Moniker,
		Network: sm.config.ChainID,
		Version: version.Version,
		Other:   []string{strconv.FormatUint(uint64(consensus.DefaultServices), 10)},
	}

	if !sm.sw.IsListening() {
		return nodeInfo
	}

	p2pListener := sm.sw.Listeners()[0]

	// We assume that the rpcListener has the same ExternalAddress.
	// This is probably true because both P2P and RPC listeners use UPnP,
	// except of course if the rpc is only bound to localhost
	if listenerStatus {
		nodeInfo.ListenAddr = cmn.Fmt("%v:%v", p2pListener.ExternalAddress().IP.String(), p2pListener.ExternalAddress().Port)
	} else {
		nodeInfo.ListenAddr = cmn.Fmt("%v:%v", p2pListener.InternalAddress().IP.String(), p2pListener.InternalAddress().Port)
	}
	return nodeInfo
}

//Start start sync manager service
func (sm *SyncManager) Start() {
	if _, err := sm.sw.Start(); err != nil {
		cmn.Exit(cmn.Fmt("fail on start SyncManager: %v", err))
	}
	// broadcast transactions
	go sm.txBroadcastLoop()
	go sm.minedBroadcastLoop()
	go sm.txSyncLoop()
}

//Stop stop sync manager
func (sm *SyncManager) Stop() {
	close(sm.quitSync)
	sm.sw.Stop()
}

func initDiscover(config *cfg.Config, priv *crypto.PrivKeyEd25519, port uint16) (*discover.Network, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	realaddr := conn.LocalAddr().(*net.UDPAddr)
	ntab, err := discover.ListenUDP(priv, conn, realaddr, path.Join(config.DBDir(), "discover.db"), nil)
	if err != nil {
		return nil, err
	}

	// add the seeds node to the discover table
	if config.P2P.Seeds == "" {
		return ntab, nil
	}
	nodes := []*discover.Node{}
	for _, seed := range strings.Split(config.P2P.Seeds, ",") {
		url := "enode://" + hex.EncodeToString(crypto.Sha256([]byte(seed))) + "@" + seed
		nodes = append(nodes, discover.MustParseNode(url))
	}
	if err = ntab.SetFallbackNodes(nodes); err != nil {
		return nil, err
	}
	return ntab, nil
}

func (sm *SyncManager) minedBroadcastLoop() {
	for {
		select {
		case blockHash := <-sm.newBlockCh:
			block, err := sm.chain.GetBlockByHash(blockHash)
			if err != nil {
				log.Errorf("Failed on mined broadcast loop get block %v", err)
				return
			}
			if err := sm.peers.broadcastMinedBlock(block); err != nil {
				log.Errorf("Broadcast mine block error. %v", err)
				return
			}
		case <-sm.quitSync:
			return
		}
	}
}

//NodeInfo get P2P peer node info
func (sm *SyncManager) NodeInfo() *p2p.NodeInfo {
	return sm.sw.NodeInfo()
}

//Peers get sync manager peer set
func (sm *SyncManager) Peers() *peerSet {
	return sm.peers
}

//Switch get sync manager switch
func (sm *SyncManager) Switch() *p2p.Switch {
	return sm.sw
}

// GetNewTxCh return a unconfirmed transaction feed channel
func (sm *SyncManager) GetNewTxCh() chan *types.Tx {
	return sm.newTxCh
}
