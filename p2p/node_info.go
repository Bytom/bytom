package p2p

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tendermint/go-crypto"

	"github.com/bytom/consensus"
	"github.com/bytom/errors"
	"github.com/bytom/protocol/bc"
)

const maxNodeInfoSize = 10240 // 10Kb

var (
	errDiffMajorVersion = errors.New("Peer is on a different major version.")
	errDiffNetwork      = errors.New("Peer is on a different network.")
	errDiffGenesis      = errors.New("Peer has different genesis.")
)

//NodeInfo peer node info
type NodeInfo struct {
	PubKey      crypto.PubKeyEd25519  `json:"pub_key"`
	Moniker     string                `json:"moniker"`
	Network     string                `json:"network"`
	RemoteAddr  string                `json:"remote_addr"`
	ListenAddr  string                `json:"listen_addr"`
	Version     string                `json:"version"` // major.minor.revision
	GenesisHash bc.Hash               `json:"genesis_hash"`
	BlockHeight uint64                `json:"block_height"`
	BlockHash   bc.Hash               `json:"block_hash"`
	ServiceFlag consensus.ServiceFlag `json:"service_flag"`
	Other       []string              `json:"other"` // other application specific data
}

type VersionCompatibleWith func(remoteVerStr string) (bool, error)

// CompatibleWith checks if two NodeInfo are compatible with eachother.
// CONTRACT: two nodes are compatible if the major version matches and network match
func (info *NodeInfo) compatibleWith(other *NodeInfo, versionCompatibleWith VersionCompatibleWith) error {
	compatible, err := versionCompatibleWith(other.Version)
	if err != nil {
		return err
	}

	if !compatible {
		return errors.Wrapf(errDiffMajorVersion, "Peer version: %v, node version: %v", other.Version, info.Version)
	}

	if info.Network != other.Network {
		return errors.Wrapf(errDiffNetwork, "Peer network: %v, node network: %v", other.Network, info.Network)
	}

	if info.GenesisHash != other.GenesisHash {
		return errors.Wrapf(errDiffGenesis, "Peer genesis hash: %x, node genesis hash: %x", other.GenesisHash, info.GenesisHash)
	}

	return nil
}

//ListenHost peer listener ip address
func (info NodeInfo) ListenHost() string {
	host, _, _ := net.SplitHostPort(info.ListenAddr)
	return host
}

//ListenPort peer listener port
func (info NodeInfo) ListenPort() int {
	_, port, _ := net.SplitHostPort(info.ListenAddr)
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return -1
	}
	return portInt
}

//RemoteAddrHost peer external ip address
func (info NodeInfo) RemoteAddrHost() string {
	host, _, _ := net.SplitHostPort(info.RemoteAddr)
	return host
}

func (info *NodeInfo) setPubKey(pubKey crypto.PubKeyEd25519) {
	info.PubKey = pubKey
}

//String representation
func (info *NodeInfo) String() string {
	return fmt.Sprintf("NodeInfo{pk: %v, moniker: %v, network: %v [listen %v], version: %v service: %v genesisHash:%v bestHeight: %v bestHash: %v}", info.PubKey, info.Moniker, info.Network, info.ListenAddr, info.Version, info.ServiceFlag, info.GenesisHash.String(), info.BlockHeight, info.BlockHash.String())
}

func (info *NodeInfo) updateBestHeight(bestHeight uint64, bestHash bc.Hash) {
	info.BlockHeight = bestHeight
	info.BlockHash = bestHash
}

func (info NodeInfo) version() string {
	return info.Version
}
