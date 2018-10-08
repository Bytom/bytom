package consensus

import (
	"encoding/binary"
	"strings"

	"github.com/bytom/protocol/bc"
)

//consensus variables
const (
	// Max gas that one block contains
	MaxBlockGas      = uint64(10000000)
	VMGasRate        = int64(200)
	StorageGasRate   = int64(1)
	MaxGasAmount     = int64(200000)
	DefaultGasCredit = int64(30000)

	//config parameter for coinbase reward
	CoinbasePendingBlockNumber = uint64(1)
	subsidyReductionInterval   = uint64(840000)
	baseSubsidy                = uint64(41250000000)
	InitialBlockSubsidy        = uint64(140700041250000000)

	// config for pow mining
	BlocksPerRetarget     = uint64(2016)
	TargetSecondsPerBlock = uint64(150)
	SeedPerRetarget       = uint64(256)

	// MaxTimeOffsetSeconds is the maximum number of seconds a block time is allowed to be ahead of the current time
	MaxTimeOffsetSeconds = uint64(60 * 60)
	MedianTimeBlocks     = 11

	PayToWitnessPubKeyHashDataSize = 20
	PayToWitnessScriptHashDataSize = 32
	CoinbaseArbitrarySizeLimit     = 128

	BTMAlias = "BTM"
)

// BTMAssetID is BTM's asset id, the soul asset of Bytom
var BTMAssetID = &bc.AssetID{
	V0: binary.BigEndian.Uint64([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
	V1: binary.BigEndian.Uint64([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
	V2: binary.BigEndian.Uint64([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
	V3: binary.BigEndian.Uint64([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
}

// InitialSeed is SHA3-256 of Byte[0^32]
var InitialSeed = &bc.Hash{
	V0: uint64(11412844483649490393),
	V1: uint64(4614157290180302959),
	V2: uint64(1780246333311066183),
	V3: uint64(9357197556716379726),
}

// BTMDefinitionMap is the ....
var BTMDefinitionMap = map[string]interface{}{
	"name":        BTMAlias,
	"symbol":      BTMAlias,
	"decimals":    8,
	"description": `Bytom Official Issue`,
}

// BlockSubsidy calculate the coinbase rewards on given block height
func BlockSubsidy(height uint64) uint64 {
	if height == 0 {
		return InitialBlockSubsidy
	}
	return baseSubsidy >> uint(height/subsidyReductionInterval)
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string, params *Params) bool {
	prefix = strings.ToLower(prefix)
	return prefix == params.Bech32HRPSegwit+"1"
}

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
type Checkpoint struct {
	Height uint64
	Hash   bc.Hash
}

// Params store the config for different network
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name            string
	Bech32HRPSegwit string
	Checkpoints     []Checkpoint
}

// ActiveNetParams is ...
var ActiveNetParams = MainNetParams

// NetParams is the correspondence between chain_id and Params
var NetParams = map[string]Params{
	"mainnet": MainNetParams,
	"wisdom":  TestNetParams,
	"solonet": SoloNetParams,
}

// MainNetParams is the config for production
var MainNetParams = Params{
	Name:            "main",
	Bech32HRPSegwit: "bm",
	Checkpoints:     []Checkpoint{
		// {10000, bc.NewHash([32]byte{0x93, 0xe1, 0xeb, 0x78, 0x21, 0xd2, 0xb4, 0xad, 0x0f, 0x5b, 0x1c, 0xea, 0x82, 0xe8, 0x43, 0xad, 0x8c, 0x09, 0x9a, 0xb6, 0x5d, 0x8f, 0x70, 0xc5, 0x84, 0xca, 0xa2, 0xdd, 0xf1, 0x74, 0x65, 0x2c})},
		// {20000, bc.NewHash([32]byte{0x7d, 0x38, 0x61, 0xf3, 0x2c, 0xc0, 0x03, 0x81, 0xbb, 0xcd, 0x9a, 0x37, 0x6f, 0x10, 0x5d, 0xfe, 0x6f, 0xfe, 0x2d, 0xa5, 0xea, 0x88, 0xa5, 0xe3, 0x42, 0xed, 0xa1, 0x17, 0x9b, 0xa8, 0x0b, 0x7c})},
		// {30000, bc.NewHash([32]byte{0x32, 0x36, 0x06, 0xd4, 0x27, 0x2e, 0x35, 0x24, 0x46, 0x26, 0x7b, 0xe0, 0xfa, 0x48, 0x10, 0xa4, 0x3b, 0xb2, 0x40, 0xf1, 0x09, 0x51, 0x5b, 0x22, 0x9f, 0xf3, 0xc3, 0x83, 0x28, 0xaa, 0x4a, 0x00})},
		// {40000, bc.NewHash([32]byte{0x7f, 0xe2, 0xde, 0x11, 0x21, 0xf3, 0xa9, 0xa0, 0xee, 0x60, 0x8d, 0x7d, 0x4b, 0xea, 0xcc, 0x33, 0xfe, 0x41, 0x25, 0xdc, 0x2f, 0x26, 0xc2, 0xf2, 0x9c, 0x07, 0x17, 0xf9, 0xe4, 0x4f, 0x9d, 0x46})},
		// {50000, bc.NewHash([32]byte{0x5e, 0xfb, 0xdf, 0xf5, 0x35, 0x38, 0xa6, 0x0b, 0x75, 0x32, 0x02, 0x61, 0x83, 0x54, 0x34, 0xff, 0x3e, 0x82, 0x2e, 0xf8, 0x64, 0xae, 0x2d, 0xc7, 0x6c, 0x9d, 0x5e, 0xbd, 0xa3, 0xd4, 0x50, 0xcf})},
		// {62000, bc.NewHash([32]byte{0xd7, 0x39, 0x8f, 0x23, 0x57, 0xf9, 0x4c, 0xa0, 0x28, 0xa7, 0x00, 0x2b, 0x53, 0x9e, 0x51, 0x2d, 0x3e, 0xca, 0xc9, 0x22, 0x59, 0xfc, 0xd0, 0x3f, 0x67, 0x1a, 0x0a, 0xb1, 0x02, 0xbf, 0x2b, 0x03})},
		// {72000, bc.NewHash([32]byte{0x66, 0x02, 0x31, 0x19, 0xf1, 0x60, 0x35, 0x61, 0xa4, 0xf1, 0x38, 0x04, 0xcc, 0xe4, 0x59, 0x8f, 0x55, 0x39, 0xba, 0x22, 0xf2, 0x6d, 0x90, 0xbf, 0xc1, 0x87, 0xef, 0x98, 0xcc, 0x70, 0x4d, 0x94})},
		// {83700, bc.NewHash([32]byte{0x7f, 0x26, 0xc9, 0x11, 0xe8, 0x46, 0xd0, 0x6e, 0x36, 0xbb, 0xac, 0xce, 0x99, 0xa2, 0x19, 0x89, 0x3f, 0xf7, 0x84, 0x2a, 0xcb, 0x44, 0x7f, 0xbb, 0x0e, 0x3b, 0xa3, 0x68, 0xd6, 0x2b, 0xe8, 0x0d})},
		// {93700, bc.NewHash([32]byte{0x70, 0x44, 0x70, 0xe5, 0xb3, 0x9b, 0xd3, 0x67, 0x19, 0x20, 0x08, 0x42, 0x1b, 0x59, 0xe8, 0xdc, 0xb5, 0xbb, 0xb9, 0x2d, 0xd3, 0xdc, 0x28, 0x4e, 0xcb, 0x7b, 0x0b, 0xbf, 0x21, 0x51, 0xe1, 0xba})},
		// {106600, bc.NewHash([32]byte{0x31, 0x15, 0x2b, 0x00, 0xd4, 0x07, 0xe1, 0xa7, 0x06, 0xe1, 0xae, 0x2e, 0x98, 0x69, 0x8f, 0x47, 0xff, 0x44, 0x97, 0x01, 0xa7, 0x9e, 0x08, 0xdb, 0xeb, 0x0f, 0x1f, 0x5a, 0xdd, 0xf5, 0x26, 0xb9})},
	},
}

// TestNetParams is the config for test-net
var TestNetParams = Params{
	Name:            "test",
	Bech32HRPSegwit: "tm",
	Checkpoints:     []Checkpoint{
		// {10303, bc.NewHash([32]byte{0x3e, 0x94, 0x5d, 0x35, 0x70, 0x30, 0xd4, 0x3b, 0x3d, 0xe3, 0xdd, 0x80, 0x67, 0x29, 0x9a, 0x5e, 0x09, 0xf9, 0xfb, 0x2b, 0xad, 0x5f, 0x92, 0xc8, 0x69, 0xd1, 0x42, 0x39, 0x74, 0x9a, 0xd1, 0x1c})},
		// {40000, bc.NewHash([32]byte{0x6b, 0x13, 0x9a, 0x5b, 0x76, 0x77, 0x9b, 0xd4, 0x1c, 0xec, 0x53, 0x68, 0x44, 0xbf, 0xf4, 0x48, 0x94, 0x3d, 0x16, 0xe3, 0x9b, 0x2e, 0xe8, 0xa1, 0x0f, 0xa0, 0xbc, 0x7d, 0x2b, 0x17, 0x55, 0xfc})},
	},
}

// SoloNetParams is the config for test-net
var SoloNetParams = Params{
	Name:            "solo",
	Bech32HRPSegwit: "sm",
	Checkpoints:     []Checkpoint{},
}
