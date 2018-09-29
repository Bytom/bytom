package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	dbm "github.com/tendermint/tmlibs/db"

	"github.com/bytom/account"
	"github.com/bytom/consensus"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
	"github.com/bytom/testutil"
)

func TestGetAccountUtxos(t *testing.T) {
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	defer os.RemoveAll("temp")

	cases := []struct {
		dbUtxos          map[string]*account.UTXO
		unconfirmedUtxos []*account.UTXO
		id               string
		unconfirmed      bool
		isSmartContract  bool
		wantUtxos        []*account.UTXO
	}{
		{
			dbUtxos:         map[string]*account.UTXO{},
			id:              "",
			unconfirmed:     false,
			isSmartContract: false,
			wantUtxos:       []*account.UTXO{},
		},
		{
			dbUtxos: map[string]*account.UTXO{
				string(account.StandardUTXOKey(bc.Hash{V0: 1})): &account.UTXO{
					OutputID: bc.Hash{V0: 1},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 2})): &account.UTXO{
					OutputID: bc.Hash{V0: 2},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 3})): &account.UTXO{
					OutputID: bc.Hash{V0: 3},
				},
				string(account.ContractUTXOKey(bc.Hash{V0: 4})): &account.UTXO{
					OutputID: bc.Hash{V0: 4},
				},
			},
			unconfirmedUtxos: []*account.UTXO{},
			id:               "",
			isSmartContract:  false,
			wantUtxos: []*account.UTXO{
				&account.UTXO{OutputID: bc.Hash{V0: 1}},
				&account.UTXO{OutputID: bc.Hash{V0: 2}},
				&account.UTXO{OutputID: bc.Hash{V0: 3}},
			},
		},
		{
			dbUtxos: map[string]*account.UTXO{
				string(account.StandardUTXOKey(bc.Hash{V0: 1})): &account.UTXO{
					OutputID: bc.Hash{V0: 1},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 2})): &account.UTXO{
					OutputID: bc.Hash{V0: 2},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 3})): &account.UTXO{
					OutputID: bc.Hash{V0: 3},
				},
				string(account.ContractUTXOKey(bc.Hash{V0: 4})): &account.UTXO{
					OutputID: bc.Hash{V0: 4},
				},
			},
			unconfirmedUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 5},
					ControlProgram: []byte("smart contract"),
				},
			},
			id:              "",
			unconfirmed:     false,
			isSmartContract: true,
			wantUtxos: []*account.UTXO{
				&account.UTXO{OutputID: bc.Hash{V0: 4}},
			},
		},
		{
			dbUtxos: map[string]*account.UTXO{
				string(account.StandardUTXOKey(bc.Hash{V0: 1})): &account.UTXO{
					OutputID: bc.Hash{V0: 1},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 1, V1: 2})): &account.UTXO{
					OutputID: bc.Hash{V0: 1, V1: 2},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 2})): &account.UTXO{
					OutputID: bc.Hash{V0: 2},
				},
				string(account.StandardUTXOKey(bc.Hash{V0: 2, V1: 2})): &account.UTXO{
					OutputID: bc.Hash{V0: 2, V1: 2},
				},
			},
			unconfirmedUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 6},
					ControlProgram: []byte{0x51},
				},
			},
			id:              "0000000000000002",
			unconfirmed:     false,
			isSmartContract: false,
			wantUtxos: []*account.UTXO{
				&account.UTXO{OutputID: bc.Hash{V0: 2}},
				&account.UTXO{OutputID: bc.Hash{V0: 2, V1: 2}},
			},
		},
		{
			dbUtxos: map[string]*account.UTXO{
				string(account.StandardUTXOKey(bc.Hash{V0: 3})): &account.UTXO{
					OutputID: bc.Hash{V0: 3},
				},
				string(account.ContractUTXOKey(bc.Hash{V0: 4})): &account.UTXO{
					OutputID: bc.Hash{V0: 4},
				},
			},
			unconfirmedUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 5},
					ControlProgram: []byte("smart contract"),
				},
				&account.UTXO{
					OutputID:       bc.Hash{V0: 6},
					ControlProgram: []byte{0x51},
				},
			},
			id:              "",
			unconfirmed:     true,
			isSmartContract: true,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 5},
					ControlProgram: []byte("smart contract"),
				},
				&account.UTXO{
					OutputID: bc.Hash{V0: 4},
				},
			},
		},
		{
			dbUtxos: map[string]*account.UTXO{
				string(account.StandardUTXOKey(bc.Hash{V0: 3})): &account.UTXO{
					OutputID: bc.Hash{V0: 3},
				},
				string(account.ContractUTXOKey(bc.Hash{V0: 4})): &account.UTXO{
					OutputID: bc.Hash{V0: 4},
				},
			},
			unconfirmedUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 5},
					ControlProgram: []byte("smart contract"),
				},
				&account.UTXO{
					OutputID:       bc.Hash{V0: 6},
					ControlProgram: []byte{0x51},
				},
			},
			id:              "",
			unconfirmed:     true,
			isSmartContract: false,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.Hash{V0: 6},
					ControlProgram: []byte{0x51},
				},
				&account.UTXO{
					OutputID: bc.Hash{V0: 3},
				},
			},
		},
	}

	w := &Wallet{DB: testDB}
	for i, c := range cases {
		for k, u := range c.dbUtxos {
			data, err := json.Marshal(u)
			if err != nil {
				t.Error(err)
			}
			testDB.Set([]byte(k), data)
		}

		w.AccountMgr = account.NewManager(testDB, nil)
		w.AccountMgr.AddUnconfirmedUtxo(c.unconfirmedUtxos)
		gotUtxos := w.GetAccountUtxos(c.id, c.unconfirmed, c.isSmartContract)
		if !testutil.DeepEqual(gotUtxos, c.wantUtxos) {
			t.Errorf("case %d: got %v want %v", i, gotUtxos, c.wantUtxos)
		}

		for k := range c.dbUtxos {
			testDB.Delete([]byte(k))
		}
	}
}

func TestFilterAccountUtxo(t *testing.T) {
	testDB := dbm.NewDB("testdb", "leveldb", "temp")
	defer os.RemoveAll("temp")

	cases := []struct {
		dbPrograms map[string]*account.CtrlProgram
		input      []*account.UTXO
		wantUtxos  []*account.UTXO
	}{
		// {
		// 	dbPrograms: map[string]*account.CtrlProgram{},
		// 	input:      []*account.UTXO{},
		// 	wantUtxos:  []*account.UTXO{},
		// },
		{
			dbPrograms: map[string]*account.CtrlProgram{
				"436f6e74726163743a2a37a64a4e15a772ab43bf3f5956d0d1f353946496788e7f40d0ff1796286a6f": &account.CtrlProgram{
					AccountID: "testAccount",
					Address:   "testAddress",
					KeyIndex:  53,
					Change:    true,
				},
			},
			input: []*account.UTXO{
				&account.UTXO{
					ControlProgram: []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         3,
				},
				&account.UTXO{
					ControlProgram: []byte{0x91},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         4,
				},
			},
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					ControlProgram:      []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:             bc.AssetID{V0: 1},
					Amount:              3,
					AccountID:           "testAccount",
					Address:             "testAddress",
					ControlProgramIndex: 53,
					Change:              true,
				},
				&account.UTXO{
					ControlProgram: []byte{0x91},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         4,
				},
			},
		},
		// {
		// 	dbPrograms: map[string]*account.CtrlProgram{},
		// 	input: []*account.UTXO{
		// 		&account.UTXO{
		// 			ControlProgram: []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
		// 			AssetID:        bc.AssetID{V0: 1},
		// 			Amount:         3,
		// 		},
		// 		&account.UTXO{
		// 			ControlProgram: []byte{0x91},
		// 			AssetID:        bc.AssetID{V0: 1},
		// 			Amount:         3,
		// 		},
		// 	},
		// 	wantUtxos: []*account.UTXO{
		// 		&account.UTXO{
		// 			ControlProgram: []byte{0x91},
		// 			AssetID:        bc.AssetID{V0: 1},
		// 			Amount:         3,
		// 		},
		// 	},
		// },
		{
			dbPrograms: map[string]*account.CtrlProgram{
				"436f6e74726163743a2a37a64a4e15a772ab43bf3f5956d0d1f353946496788e7f40d0ff1796286a6f": &account.CtrlProgram{
					AccountID: "testAccount",
					Address:   "testAddress",
					KeyIndex:  53,
					Change:    true,
				},
				"436f6e74726163743adb4d86262c12ba70d50b3ca3ae102d5682436243bd1e8c79569603f75675036a": &account.CtrlProgram{
					AccountID: "testAccount2",
					Address:   "testAddress2",
					KeyIndex:  72,
					Change:    false,
				},
			},
			input: []*account.UTXO{
				&account.UTXO{
					ControlProgram: []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         3,
				},
				&account.UTXO{
					ControlProgram: []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         5,
				},
				&account.UTXO{
					ControlProgram: []byte{0x00, 0x14, 0xc6, 0xbf, 0x22, 0x19, 0x64, 0x2a, 0xc5, 0x9e, 0x5b, 0xe4, 0xeb, 0xdf, 0x5b, 0x22, 0x49, 0x56, 0xa7, 0x98, 0xa4, 0xdf},
					AssetID:        bc.AssetID{V0: 1},
					Amount:         7,
				},
			},
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					ControlProgram:      []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:             bc.AssetID{V0: 1},
					Amount:              3,
					AccountID:           "testAccount",
					Address:             "testAddress",
					ControlProgramIndex: 53,
					Change:              true,
				},
				&account.UTXO{
					ControlProgram:      []byte{0x00, 0x14, 0x62, 0x50, 0x18, 0xb6, 0x85, 0x77, 0xba, 0x9b, 0x26, 0x19, 0xc8, 0x1d, 0x2e, 0x96, 0xba, 0x22, 0xbe, 0x77, 0x77, 0xd7},
					AssetID:             bc.AssetID{V0: 1},
					Amount:              5,
					AccountID:           "testAccount",
					Address:             "testAddress",
					ControlProgramIndex: 53,
					Change:              true,
				},
				&account.UTXO{
					ControlProgram:      []byte{0x00, 0x14, 0xc6, 0xbf, 0x22, 0x19, 0x64, 0x2a, 0xc5, 0x9e, 0x5b, 0xe4, 0xeb, 0xdf, 0x5b, 0x22, 0x49, 0x56, 0xa7, 0x98, 0xa4, 0xdf},
					AssetID:             bc.AssetID{V0: 1},
					Amount:              7,
					AccountID:           "testAccount2",
					Address:             "testAddress2",
					ControlProgramIndex: 72,
					Change:              false,
				},
			},
		},
	}

	w := &Wallet{DB: testDB}
	for i, c := range cases {
		for s, p := range c.dbPrograms {
			data, err := json.Marshal(p)
			if err != nil {
				t.Error(err)
			}
			key, err := hex.DecodeString(s)
			if err != nil {
				t.Error(err)
			}
			testDB.Set(key, data)
		}

		gotUtxos := w.filterAccountUtxo(c.input)
		sort.Slice(gotUtxos[:], func(i, j int) bool {
			return gotUtxos[i].Amount < gotUtxos[j].Amount
		})

		if !testutil.DeepEqual(gotUtxos, c.wantUtxos) {
			t.Errorf("case %d: got %x want %x", i, gotUtxos, c.wantUtxos)

			if len(gotUtxos) != 0 {
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].ControlProgram, c.wantUtxos[0].ControlProgram)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].AssetID, c.wantUtxos[0].AssetID)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].Amount, c.wantUtxos[0].Amount)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].AccountID, c.wantUtxos[0].AccountID)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].Address, c.wantUtxos[0].Address)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].ControlProgramIndex, c.wantUtxos[0].ControlProgramIndex)
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[0].Change, c.wantUtxos[0].Change)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].ControlProgram, c.wantUtxos[1].ControlProgram)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].AssetID, c.wantUtxos[1].AssetID)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].Amount, c.wantUtxos[1].Amount)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].AccountID, c.wantUtxos[1].AccountID)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].Address, c.wantUtxos[1].Address)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].ControlProgramIndex, c.wantUtxos[1].ControlProgramIndex)
				// fmt.Printf("case %d: got %v want %v\n", i, gotUtxos[1].Change, c.wantUtxos[1].Change)
			} else {
				fmt.Printf("case %d: got %v want %v\n", i, gotUtxos, c.wantUtxos)
			}

		}
		for s := range c.dbPrograms {
			key, err := hex.DecodeString(s)
			if err != nil {
				t.Error(err)
			}
			testDB.Delete(key)
		}
	}
}

func TestTxInToUtxos(t *testing.T) {
	cases := []struct {
		tx         *types.Tx
		statusFail bool
		wantUtxos  []*account.UTXO
	}{
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewCoinbaseInput([]byte{0x51}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(*consensus.BTMAssetID, 41250000000, []byte{0x51}),
				},
			}),
			statusFail: false,
			wantUtxos:  []*account.UTXO{},
		},
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewIssuanceInput([]byte{}, 4125, []byte{0x51}, [][]byte{}, []byte{}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(*consensus.BTMAssetID, 4125, []byte{0x51}),
				},
			}),
			statusFail: false,
			wantUtxos:  []*account.UTXO{},
		},
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 1}, bc.AssetID{V0: 1}, 1, 1, []byte{0x51}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 2}, bc.AssetID{V0: 1}, 3, 2, []byte{0x52}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 3}, *consensus.BTMAssetID, 5, 3, []byte{0x53}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 4}, *consensus.BTMAssetID, 7, 4, []byte{0x54}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(bc.AssetID{V0: 1}, 4, []byte{0x51}),
					types.NewTxOutput(*consensus.BTMAssetID, 12, []byte{0x53}),
				},
			}),
			statusFail: false,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0xd2, 0xc8, 0xd4, 0xec, 0xcd, 0x2e, 0x1d, 0xeb, 0x81, 0xdc, 0xd4, 0xc0, 0xb9, 0x8a, 0x70, 0x85, 0xf1, 0x70, 0xe4, 0x83, 0x82, 0xf5, 0x25, 0x1a, 0xa0, 0x86, 0x5b, 0xd9, 0xb6, 0x06, 0x5a, 0x20}),
					AssetID:        bc.AssetID{V0: 1},
					Amount:         1,
					ControlProgram: []byte{0x51},
					SourceID:       bc.Hash{V0: 1},
					SourcePos:      1,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x9a, 0x0d, 0xea, 0x25, 0x60, 0x38, 0x43, 0x6f, 0xd1, 0xbe, 0xce, 0xbb, 0xc4, 0xaa, 0xec, 0x8b, 0x42, 0x9a, 0xe5, 0x21, 0xfa, 0x76, 0xe4, 0x62, 0x85, 0x53, 0x41, 0xd2, 0xc7, 0x35, 0xbc, 0x09}),
					AssetID:        bc.AssetID{V0: 1},
					Amount:         3,
					ControlProgram: []byte{0x52},
					SourceID:       bc.Hash{V0: 2},
					SourcePos:      2,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x45, 0x36, 0x7c, 0x22, 0x18, 0x02, 0xf4, 0x52, 0xae, 0x08, 0xcc, 0x0b, 0xff, 0xcd, 0xa6, 0xb3, 0x24, 0x7b, 0xbf, 0xd2, 0x13, 0xc7, 0xf7, 0x45, 0xe9, 0x6a, 0xb2, 0xa7, 0x11, 0xbb, 0xb4, 0x19}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         5,
					ControlProgram: []byte{0x53},
					SourceID:       bc.Hash{V0: 3},
					SourcePos:      3,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x79, 0xe5, 0x0d, 0x09, 0xb5, 0xf6, 0x82, 0x9c, 0xeb, 0x45, 0xab, 0x45, 0x25, 0xc3, 0xed, 0x86, 0xd9, 0x49, 0xa0, 0xbf, 0xa4, 0x1e, 0x64, 0xf3, 0x70, 0x7a, 0x68, 0x5d, 0x57, 0x48, 0x4d, 0xd8}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         7,
					ControlProgram: []byte{0x54},
					SourceID:       bc.Hash{V0: 4},
					SourcePos:      4,
				},
			},
		},
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 1}, bc.AssetID{V0: 1}, 1, 1, []byte{0x51}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 2}, bc.AssetID{V0: 1}, 3, 2, []byte{0x52}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 3}, *consensus.BTMAssetID, 5, 3, []byte{0x53}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 4}, *consensus.BTMAssetID, 7, 4, []byte{0x54}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(bc.AssetID{V0: 1}, 4, []byte{0x51}),
					types.NewTxOutput(*consensus.BTMAssetID, 12, []byte{0x53}),
				},
			}),
			statusFail: true,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x45, 0x36, 0x7c, 0x22, 0x18, 0x02, 0xf4, 0x52, 0xae, 0x08, 0xcc, 0x0b, 0xff, 0xcd, 0xa6, 0xb3, 0x24, 0x7b, 0xbf, 0xd2, 0x13, 0xc7, 0xf7, 0x45, 0xe9, 0x6a, 0xb2, 0xa7, 0x11, 0xbb, 0xb4, 0x19}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         5,
					ControlProgram: []byte{0x53},
					SourceID:       bc.Hash{V0: 3},
					SourcePos:      3,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x79, 0xe5, 0x0d, 0x09, 0xb5, 0xf6, 0x82, 0x9c, 0xeb, 0x45, 0xab, 0x45, 0x25, 0xc3, 0xed, 0x86, 0xd9, 0x49, 0xa0, 0xbf, 0xa4, 0x1e, 0x64, 0xf3, 0x70, 0x7a, 0x68, 0x5d, 0x57, 0x48, 0x4d, 0xd8}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         7,
					ControlProgram: []byte{0x54},
					SourceID:       bc.Hash{V0: 4},
					SourcePos:      4,
				},
			},
		},
	}

	for i, c := range cases {
		if gotUtxos := txInToUtxos(c.tx, c.statusFail); !testutil.DeepEqual(gotUtxos, c.wantUtxos) {
			for k, v := range gotUtxos {
				data, _ := json.Marshal(v)
				fmt.Println(k, string(data))
			}
			for k, v := range c.wantUtxos {
				data, _ := json.Marshal(v)
				fmt.Println(k, string(data))
			}
			t.Errorf("case %d: got %v want %v", i, gotUtxos, c.wantUtxos)
		}
	}
}

func TestTxOutToUtxos(t *testing.T) {
	cases := []struct {
		tx          *types.Tx
		statusFail  bool
		vaildHeight uint64
		wantUtxos   []*account.UTXO
	}{
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewCoinbaseInput([]byte{0x51}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(*consensus.BTMAssetID, 41250000000, []byte{0x51}),
				},
			}),
			statusFail:  false,
			vaildHeight: 98,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x98, 0x7e, 0xf4, 0xa7, 0x42, 0x19, 0x0b, 0x0a, 0x67, 0xd6, 0x25, 0xec, 0xd7, 0xad, 0x61, 0x93, 0x19, 0x4e, 0xff, 0x8a, 0x90, 0x28, 0xc9, 0x9d, 0x29, 0x7e, 0x13, 0x77, 0xa1, 0xcd, 0x70, 0x6e}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         41250000000,
					ControlProgram: []byte{0x51},
					SourceID:       bc.NewHash([32]byte{0x70, 0x29, 0xb0, 0xaa, 0x28, 0xd9, 0x24, 0x87, 0x76, 0x14, 0x6e, 0x6e, 0x53, 0x5d, 0x23, 0x64, 0x3d, 0xd6, 0x6d, 0x52, 0x57, 0x4f, 0x78, 0x5c, 0xdb, 0x85, 0x36, 0xab, 0x21, 0x76, 0xe9, 0x79}),
					SourcePos:      0,
					ValidHeight:    98,
				},
			},
		},
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 1}, bc.AssetID{V0: 1}, 5, 1, []byte{0x51}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 2}, *consensus.BTMAssetID, 7, 1, []byte{0x51}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(bc.AssetID{V0: 1}, 2, []byte{0x51}),
					types.NewTxOutput(bc.AssetID{V0: 1}, 3, []byte{0x52}),
					types.NewTxOutput(*consensus.BTMAssetID, 2, []byte{0x53}),
					types.NewTxOutput(*consensus.BTMAssetID, 5, []byte{0x54}),
				},
			}),
			statusFail:  false,
			vaildHeight: 0,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x7d, 0x96, 0xca, 0x93, 0xa7, 0xaa, 0xec, 0xaf, 0x0e, 0x71, 0x27, 0x90, 0xaa, 0x8c, 0x44, 0x35, 0x9d, 0xa3, 0x52, 0xcd, 0x59, 0x84, 0x55, 0xf4, 0x44, 0x10, 0x26, 0x81, 0x34, 0x8d, 0x64, 0x80}),
					AssetID:        bc.AssetID{V0: 1},
					Amount:         2,
					ControlProgram: []byte{0x51},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      0,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x18, 0x8f, 0x87, 0xc5, 0x66, 0xf4, 0x1b, 0x8b, 0xe2, 0xcc, 0x8b, 0x54, 0x59, 0x54, 0xb0, 0x97, 0x23, 0x36, 0x7f, 0xe9, 0xbe, 0x95, 0x84, 0x8e, 0xbc, 0x0b, 0xd9, 0xe1, 0xb2, 0x98, 0x41, 0x97}),
					AssetID:        bc.AssetID{V0: 1},
					Amount:         3,
					ControlProgram: []byte{0x52},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      1,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x86, 0x5f, 0xfa, 0xda, 0xb7, 0xf8, 0xee, 0x8c, 0xbf, 0x28, 0x27, 0x7e, 0x4a, 0xa2, 0xb7, 0x83, 0xf1, 0xe0, 0xc3, 0x87, 0x5c, 0x0d, 0x61, 0x4f, 0x86, 0x81, 0xe0, 0xaa, 0x98, 0xf9, 0x0d, 0x55}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         2,
					ControlProgram: []byte{0x53},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      2,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x37, 0x18, 0x24, 0x62, 0x80, 0x8d, 0x7e, 0x78, 0x37, 0x4d, 0x08, 0x19, 0x18, 0x9c, 0x35, 0xc1, 0x85, 0x0c, 0x45, 0x87, 0x68, 0x0f, 0x69, 0x57, 0x6c, 0x44, 0x4a, 0xbd, 0x5b, 0x15, 0xf7, 0x03}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         5,
					ControlProgram: []byte{0x54},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      3,
				},
			},
		},
		{
			tx: types.NewTx(types.TxData{
				Inputs: []*types.TxInput{
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 1}, bc.AssetID{V0: 1}, 5, 1, []byte{0x51}),
					types.NewSpendInput([][]byte{}, bc.Hash{V0: 2}, *consensus.BTMAssetID, 7, 1, []byte{0x51}),
				},
				Outputs: []*types.TxOutput{
					types.NewTxOutput(bc.AssetID{V0: 1}, 2, []byte{0x51}),
					types.NewTxOutput(bc.AssetID{V0: 1}, 3, []byte{0x52}),
					types.NewTxOutput(*consensus.BTMAssetID, 2, []byte{0x53}),
					types.NewTxOutput(*consensus.BTMAssetID, 5, []byte{0x54}),
				},
			}),
			statusFail:  true,
			vaildHeight: 0,
			wantUtxos: []*account.UTXO{
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x86, 0x5f, 0xfa, 0xda, 0xb7, 0xf8, 0xee, 0x8c, 0xbf, 0x28, 0x27, 0x7e, 0x4a, 0xa2, 0xb7, 0x83, 0xf1, 0xe0, 0xc3, 0x87, 0x5c, 0x0d, 0x61, 0x4f, 0x86, 0x81, 0xe0, 0xaa, 0x98, 0xf9, 0x0d, 0x55}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         2,
					ControlProgram: []byte{0x53},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      2,
				},
				&account.UTXO{
					OutputID:       bc.NewHash([32]byte{0x37, 0x18, 0x24, 0x62, 0x80, 0x8d, 0x7e, 0x78, 0x37, 0x4d, 0x08, 0x19, 0x18, 0x9c, 0x35, 0xc1, 0x85, 0x0c, 0x45, 0x87, 0x68, 0x0f, 0x69, 0x57, 0x6c, 0x44, 0x4a, 0xbd, 0x5b, 0x15, 0xf7, 0x03}),
					AssetID:        *consensus.BTMAssetID,
					Amount:         5,
					ControlProgram: []byte{0x54},
					SourceID:       bc.NewHash([32]byte{0xec, 0xb2, 0xf0, 0xfb, 0xcb, 0xf5, 0x73, 0x7d, 0xae, 0x8e, 0x59, 0x5e, 0x75, 0x3c, 0xe2, 0x65, 0x5a, 0xff, 0x50, 0x5d, 0xb4, 0x40, 0x65, 0xd1, 0xa5, 0xdb, 0xa0, 0x4a, 0x99, 0xb1, 0xa4, 0xd4}),
					SourcePos:      3,
				},
			},
		},
	}

	for i, c := range cases {
		if gotUtxos := txOutToUtxos(c.tx, c.statusFail, c.vaildHeight); !testutil.DeepEqual(gotUtxos, c.wantUtxos) {
			t.Errorf("case %d: got %v want %v", i, gotUtxos, c.wantUtxos)
		}
	}
}
