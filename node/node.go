package node

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/prometheus/prometheus/util/flock"
	log "github.com/sirupsen/logrus"
	"github.com/tendermint/go-crypto"
	cmn "github.com/tendermint/tmlibs/common"
	dbm "github.com/tendermint/tmlibs/db"
	browser "github.com/toqueteos/webbrowser"

	"github.com/bytom/accesstoken"
	"github.com/bytom/account"
	"github.com/bytom/api"
	"github.com/bytom/asset"
	"github.com/bytom/blockchain/pseudohsm"
	"github.com/bytom/blockchain/txfeed"
	cfg "github.com/bytom/config"
	"github.com/bytom/consensus"
	"github.com/bytom/database/leveldb"
	"github.com/bytom/env"
	"github.com/bytom/event"
	"github.com/bytom/mining/cpuminer"
	"github.com/bytom/mining/miningpool"
	"github.com/bytom/mining/tensority"
	"github.com/bytom/net/websocket"
	"github.com/bytom/netsync"
	"github.com/bytom/p2p"
	"github.com/bytom/p2p/discover"
	"github.com/bytom/protocol"
	w "github.com/bytom/wallet"
)

const webHost = "http://127.0.0.1"

// Node represent bytom node
type Node struct {
	cmn.BaseService

	config          *cfg.Config
	eventDispatcher *event.Dispatcher
	syncManager     *netsync.SyncManager

	wallet          *w.Wallet
	accessTokens    *accesstoken.CredentialStore
	notificationMgr *websocket.WSNotificationManager
	api             *api.API
	chain           *protocol.Chain
	txfeed          *txfeed.Tracker
	cpuMiner        *cpuminer.CPUMiner
	miningPool      *miningpool.MiningPool
	miningEnable    bool
}

// NewNode create bytom node
func NewNode(config *cfg.Config) *Node {
	ctx := context.Background()
	if err := lockDataDirectory(config); err != nil {
		cmn.Exit("Error: " + err.Error())
	}
	initLogFile(config)
	initActiveNetParams(config)
	initCommonConfig(config)

	// Get store
	if config.DBBackend != "memdb" && config.DBBackend != "leveldb" {
		cmn.Exit(cmn.Fmt("Param db_backend [%v] is invalid, use leveldb or memdb", config.DBBackend))
	}
	coreDB := dbm.NewDB("core", config.DBBackend, config.DBDir())
	store := leveldb.NewStore(coreDB)

	tokenDB := dbm.NewDB("accesstoken", config.DBBackend, config.DBDir())
	accessTokens := accesstoken.NewStore(tokenDB)

	txPool := protocol.NewTxPool(store)
	chain, err := protocol.NewChain(store, txPool)
	if err != nil {
		cmn.Exit(cmn.Fmt("Failed to create chain structure: %v", err))
	}

	var accounts *account.Manager
	var assets *asset.Registry
	var wallet *w.Wallet
	var txFeed *txfeed.Tracker

	txFeedDB := dbm.NewDB("txfeeds", config.DBBackend, config.DBDir())
	txFeed = txfeed.NewTracker(txFeedDB, chain)

	if err = txFeed.Prepare(ctx); err != nil {
		log.WithField("error", err).Error("start txfeed")
		return nil
	}

	hsm, err := pseudohsm.New(config.KeysDir())
	if err != nil {
		cmn.Exit(cmn.Fmt("initialize HSM failed: %v", err))
	}

	if !config.Wallet.Disable {
		walletDB := dbm.NewDB("wallet", config.DBBackend, config.DBDir())
		accounts = account.NewManager(walletDB, chain)
		assets = asset.NewRegistry(walletDB, chain)
		wallet, err = w.NewWallet(walletDB, accounts, assets, hsm, chain)
		if err != nil {
			log.WithField("error", err).Error("init NewWallet")
		}

		// trigger rescan wallet
		if config.Wallet.Rescan {
			wallet.RescanBlocks()
		}
	}
	dispatcher := event.NewDispatcher()
	blacklistDB := dbm.NewDB("trusthistory", config.DBBackend, config.DBDir())
	privKey := crypto.GenPrivKeyEd25519()
	// Create & add listener
	var l p2p.Listener
	var listenAddr string

	if !config.VaultMode {
		l, listenAddr = p2p.GetListener(config.P2P)
	}

	discover, err := discover.NewDiscover(config, &privKey, l.ExternalAddress().Port)
	if err != nil {
		cmn.Exit(cmn.Fmt("Failed to create p2p discover: %v", err))
	}

	sw, err := p2p.NewSwitch(discover, blacklistDB, l, config, privKey, listenAddr)
	if err != nil {
		cmn.Exit(cmn.Fmt("Failed to create p2p switch: %v", err))
	}

	syncManager, err := netsync.NewSyncManager(sw, chain, config, txPool, dispatcher)
	if err != nil {
		cmn.Exit(cmn.Fmt("Failed to create sync manager: %v", err))
	}

	notificationMgr := websocket.NewWsNotificationManager(config.Websocket.MaxNumWebsockets, config.Websocket.MaxNumConcurrentReqs, chain)

	// get transaction from txPool and send it to syncManager and wallet
	go newPoolTxListener(txPool, syncManager, wallet, notificationMgr)

	// run the profile server
	profileHost := config.ProfListenAddress
	if profileHost != "" {
		// Profiling bytomd programs.see (https://blog.golang.org/profiling-go-programs)
		// go tool pprof http://profileHose/debug/pprof/heap
		go func() {
			if err = http.ListenAndServe(profileHost, nil); err != nil {
				cmn.Exit(cmn.Fmt("Failed to register tcp profileHost: %v", err))
			}
		}()
	}

	node := &Node{
		eventDispatcher: dispatcher,
		config:          config,
		syncManager:     syncManager,
		accessTokens:    accessTokens,
		wallet:          wallet,
		chain:           chain,
		txfeed:          txFeed,
		miningEnable:    config.Mining.Enable,

		notificationMgr: notificationMgr,
	}

	node.cpuMiner = cpuminer.NewCPUMiner(chain, accounts, txPool, dispatcher)
	node.miningPool = miningpool.NewMiningPool(chain, accounts, txPool, dispatcher, config.Mining.RecommitInterval)

	node.BaseService = *cmn.NewBaseService(nil, "Node", node)

	if config.Simd.Enable {
		tensority.UseSIMD = true
	}

	return node
}

// newPoolTxListener listener transaction from txPool, and send it to syncManager and wallet
func newPoolTxListener(txPool *protocol.TxPool, syncManager *netsync.SyncManager, wallet *w.Wallet, notificationMgr *websocket.WSNotificationManager) {
	txMsgCh := txPool.GetMsgCh()
	syncManagerTxCh := syncManager.GetNewTxCh()

	for {
		msg := <-txMsgCh
		switch msg.MsgType {
		case protocol.MsgNewTx:
			syncManagerTxCh <- msg.Tx
			if wallet != nil {
				wallet.AddUnconfirmedTx(msg.TxDesc)
			}
			notificationMgr.NotifyMempoolTx(msg.Tx)
		case protocol.MsgRemoveTx:
			if wallet != nil {
				wallet.RemoveUnconfirmedTx(msg.TxDesc)
			}
		default:
			log.Warn("got unknow message type from the txPool channel")
		}
	}
}

// Lock data directory after daemonization
func lockDataDirectory(config *cfg.Config) error {
	_, _, err := flock.New(filepath.Join(config.RootDir, "LOCK"))
	if err != nil {
		return errors.New("datadir already used by another process")
	}
	return nil
}

func initActiveNetParams(config *cfg.Config) {
	var exist bool
	consensus.ActiveNetParams, exist = consensus.NetParams[config.ChainID]
	if !exist {
		cmn.Exit(cmn.Fmt("chain_id[%v] don't exist", config.ChainID))
	}
}

func initLogFile(config *cfg.Config) {
	if config.LogFile == "" {
		return
	}
	cmn.EnsureDir(filepath.Dir(config.LogFile), 0700)
	file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.WithField("err", err).Info("using default")
	}

}

func initCommonConfig(config *cfg.Config) {
	cfg.CommonConfig = config
}

// Lanch web broser or not
func launchWebBrowser(port string) {
	webAddress := webHost + ":" + port
	log.Info("Launching System Browser with :", webAddress)
	if err := browser.Open(webAddress); err != nil {
		log.Error(err.Error())
		return
	}
}

func (n *Node) initAndstartApiServer() {
	n.api = api.NewAPI(n.syncManager, n.wallet, n.txfeed, n.cpuMiner, n.miningPool, n.chain, n.config, n.accessTokens, n.eventDispatcher, n.notificationMgr)

	listenAddr := env.String("LISTEN", n.config.ApiAddress)
	env.Parse()
	n.api.StartServer(*listenAddr)
}

func (n *Node) OnStart() error {
	if n.miningEnable {
		if _, err := n.wallet.AccountMgr.GetMiningAddress(); err != nil {
			n.miningEnable = false
			log.Error(err)
		} else {
			n.cpuMiner.Start()
		}
	}
	if !n.config.VaultMode {
		if err := n.syncManager.Start(); err != nil {
			return err
		}
	}

	n.initAndstartApiServer()
	n.notificationMgr.Start()
	if !n.config.Web.Closed {
		_, port, err := net.SplitHostPort(n.config.ApiAddress)
		if err != nil {
			log.Error("Invalid api address")
			return err
		}
		launchWebBrowser(port)
	}
	return nil
}

func (n *Node) OnStop() {
	n.notificationMgr.Shutdown()
	n.notificationMgr.WaitForShutdown()
	n.BaseService.OnStop()
	if n.miningEnable {
		n.cpuMiner.Stop()
	}
	if !n.config.VaultMode {
		n.syncManager.Stop()
	}
	n.eventDispatcher.Stop()
}

func (n *Node) RunForever() {
	// Sleep forever and then...
	cmn.TrapSignal(func() {
		n.Stop()
	})
}

func (n *Node) SyncManager() *netsync.SyncManager {
	return n.syncManager
}

func (n *Node) MiningPool() *miningpool.MiningPool {
	return n.miningPool
}
