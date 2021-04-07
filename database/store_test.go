package database

import (
	"bytes"
	"encoding/hex"
	"github.com/bytom/bytom/crypto/sha3pool"
	"os"
	"testing"

	"github.com/bytom/bytom/config"
	dbm "github.com/bytom/bytom/database/leveldb"
	"github.com/bytom/bytom/database/storage"
	"github.com/bytom/bytom/protocol"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
	"github.com/bytom/bytom/protocol/state"
	"github.com/bytom/bytom/testutil"
)

func TestLoadBlockIndex(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	block := config.GenesisBlock()
	txStatus := bc.NewTransactionStatus()

	if err := store.SaveBlock(block, txStatus); err != nil {
		t.Fatal(err)
	}

	for block.Height <= 128 {
		preHash := block.Hash()
		block.PreviousBlockHash = preHash
		block.Height++
		if err := store.SaveBlock(block, txStatus); err != nil {
			t.Fatal(err)
		}

		if block.Height%32 != 0 {
			continue
		}

		for i := uint64(0); i < block.Height/32; i++ {
			block.Nonce++
			if err := store.SaveBlock(block, txStatus); err != nil {
				t.Fatal(err)
			}
		}
	}

	if _, err := store.LoadBlockIndex(128); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBlockIndexBestHeight(t *testing.T) {
	cases := []struct {
		blockBestHeight uint64
		stateBestHeight uint64
	}{
		{
			blockBestHeight: 100,
			stateBestHeight: 90,
		},
		{
			blockBestHeight: 100,
			stateBestHeight: 0,
		},
		{
			blockBestHeight: 100,
			stateBestHeight: 100,
		},
	}

	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)
	var savedBlocks []types.Block

	for _, c := range cases {
		block := config.GenesisBlock()
		txStatus := bc.NewTransactionStatus()

		for i := uint64(0); i < c.blockBestHeight; i++ {
			if err := store.SaveBlock(block, txStatus); err != nil {
				t.Fatal(err)
			}

			savedBlocks = append(savedBlocks, *block)
			block.PreviousBlockHash = block.Hash()
			block.Height++
		}

		index, err := store.LoadBlockIndex(c.stateBestHeight)
		if err != nil {
			t.Fatal(err)
		}

		for _, block := range savedBlocks {
			blockHash := block.Hash()
			if block.Height <= c.stateBestHeight != index.BlockExist(&blockHash) {
				t.Errorf("Error in load block index")
			}
		}
	}
}

func TestLoadBlockIndexEquals(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	block := config.GenesisBlock()
	txStatus := bc.NewTransactionStatus()
	expectBlockIndex := state.NewBlockIndex()
	var parent *state.BlockNode

	for block.Height <= 100 {
		if err := store.SaveBlock(block, txStatus); err != nil {
			t.Fatal(err)
		}

		if block.Height != 0 {
			parent = expectBlockIndex.GetNode(&block.PreviousBlockHash)
		}

		node, err := state.NewBlockNode(&block.BlockHeader, parent)
		if err != nil {
			t.Fatal(err)
		}

		expectBlockIndex.AddNode(node)
		block.PreviousBlockHash = block.Hash()
		block.Height++
	}

	index, err := store.LoadBlockIndex(100)
	if err != nil {
		t.Fatal(err)
	}

	if !testutil.DeepEqual(expectBlockIndex, index) {
		t.Errorf("got block index:%v, expect block index:%v", index, expectBlockIndex)
	}
}
func TestSaveChainStatus(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	node := &state.BlockNode{Height: 100, Hash: bc.Hash{V0: 0, V1: 1, V2: 2, V3: 3}}
	view := &state.UtxoViewpoint{
		Entries: map[bc.Hash]*storage.UtxoEntry{
			bc.Hash{V0: 1, V1: 2, V2: 3, V3: 4}: &storage.UtxoEntry{IsCoinBase: false, BlockHeight: 100, Spent: false},
			bc.Hash{V0: 1, V1: 2, V2: 3, V3: 4}: &storage.UtxoEntry{IsCoinBase: true, BlockHeight: 100, Spent: true},
			bc.Hash{V0: 1, V1: 1, V2: 3, V3: 4}: &storage.UtxoEntry{IsCoinBase: false, BlockHeight: 100, Spent: true},
		},
	}

	if err := store.SaveChainStatus(node, view); err != nil {
		t.Fatal(err)
	}

	expectStatus := &protocol.BlockStoreState{Height: node.Height, Hash: &node.Hash}
	if !testutil.DeepEqual(store.GetStoreStatus(), expectStatus) {
		t.Errorf("got block status:%v, expect block status:%v", store.GetStoreStatus(), expectStatus)
	}

	for hash, utxo := range view.Entries {
		if utxo.Spent && !utxo.IsCoinBase {
			continue
		}

		gotUtxo, err := store.GetUtxo(&hash)
		if err != nil {
			t.Fatal(err)
		}

		if !testutil.DeepEqual(utxo, gotUtxo) {
			t.Errorf("got utxo entry:%v, expect utxo entry:%v", gotUtxo, utxo)
		}
	}
}

func TestSaveBlock(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	block := config.GenesisBlock()
	status := &bc.TransactionStatus{VerifyStatus: []*bc.TxVerifyResult{{StatusFail: true}}}
	if err := store.SaveBlock(block, status); err != nil {
		t.Fatal(err)
	}

	blockHash := block.Hash()
	gotBlock, err := store.GetBlock(&blockHash)
	if err != nil {
		t.Fatal(err)
	}

	gotBlock.Transactions[0].Tx.SerializedSize = 0
	gotBlock.Transactions[0].SerializedSize = 0
	if !testutil.DeepEqual(block, gotBlock) {
		t.Errorf("got block:%v, expect block:%v", gotBlock, block)
	}

	gotStatus, err := store.GetTransactionStatus(&blockHash)
	if err != nil {
		t.Fatal(err)
	}

	if !testutil.DeepEqual(status, gotStatus) {
		t.Errorf("got status:%v, expect status:%v", gotStatus, status)
	}

	data := store.db.Get(CalcBlockHeaderKey(block.Height, &blockHash))
	gotBlockHeader := types.BlockHeader{}
	if err := gotBlockHeader.UnmarshalText(data); err != nil {
		t.Fatal(err)
	}

	if !testutil.DeepEqual(block.BlockHeader, gotBlockHeader) {
		t.Errorf("got block header:%v, expect block header:%v", gotBlockHeader, block.BlockHeader)
	}
}

func TestStore_SaveContract(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	code, err := hex.DecodeString("6a4c04626372704c01014c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0")
	if err != nil {
		t.Fatal(err)
	}

	program := &bc.Program{VmVersion: 1, Code: code}
	txID := &bc.Hash{V0: 0, V1: 1, V2: 2, V3: 3}
	if err := store.SaveContract(program, txID); err != nil {
		t.Fatal(err)
	}

	txID1 := &bc.Hash{V0: 1, V1: 1, V2: 1, V3: 1}
	if err := store.SaveContract(program, txID1); err != nil {
		t.Fatal(err)
	}

	var hash [32]byte
	sha3pool.Sum256(hash[:], program.Code)

	codeData := store.db.Get(CalcContractKey(hash))
	if codeData == nil {
		t.Errorf("can't find the registered contract by contract hash %v", hash)
	}

	if !bytes.Equal(codeData, program.Code) {
		t.Errorf("got program code: %v, expect program code: %v", codeData, program.Code)
	}

	txIDData := store.db.Get(CalcContractTxKey(hash))
	if txIDData == nil {
		t.Errorf("can't find the transaction id by contract hash %v", hash)
	}

	if !bytes.Equal(txIDData, txID.Bytes()) {
		t.Errorf("got transaction id: %v, expect transaction id: %v", txIDData, txID.Bytes())
	}
}

func TestStore_DeleteContract(t *testing.T) {
	defer os.RemoveAll("temp")
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	store := NewStore(testDB)

	code, err := hex.DecodeString("6a4c04626372704c01014c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0")
	if err != nil {
		t.Fatal(err)
	}

	program := &bc.Program{VmVersion: 1, Code: code}
	txID := &bc.Hash{V0: 0, V1: 1, V2: 2, V3: 3}
	if err := store.SaveContract(program, txID); err != nil {
		t.Fatal(err)
	}

	var hash [32]byte
	sha3pool.Sum256(hash[:], program.Code)

	txID1 := &bc.Hash{V0: 1, V1: 1, V2: 1, V3: 1}
	if err := store.DeleteContract(program, txID1); err != nil {
		t.Fatal(err)
	}

	codeData := store.db.Get(CalcContractKey(hash))
	if codeData == nil {
		t.Errorf("can't find the registered contract by contract hash %v", hash)
	}

	txIDData := store.db.Get(CalcContractTxKey(hash))
	if txIDData == nil {
		t.Errorf("can't find the transaction id by contract hash %v", hash)
	}

	if err := store.DeleteContract(program, txID); err != nil {
		t.Fatal(err)
	}

	codeData = store.db.Get(CalcContractKey(hash))
	if codeData != nil {
		t.Errorf("registered contract should be deleted")
	}

	txIDData = store.db.Get(CalcContractTxKey(hash))
	if txIDData != nil {
		t.Errorf("transaction id should be deleted")
	}
}
