package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/groupcache/lru"

	"github.com/bytom/consensus"
	"github.com/bytom/database/storage"
	"github.com/bytom/event"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
	"github.com/bytom/protocol/state"
	"github.com/bytom/protocol/validation"
	"github.com/bytom/testutil"
)

var testTxs = []*types.Tx{
	types.NewTx(types.TxData{
		SerializedSize: 100,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, bc.NewHash([32]byte{0x01}), *consensus.BTMAssetID, 1, 1, []byte{0x51}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(*consensus.BTMAssetID, 1, []byte{0x6a}),
		},
	}),
	types.NewTx(types.TxData{
		SerializedSize: 100,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, bc.NewHash([32]byte{0x01}), *consensus.BTMAssetID, 1, 1, []byte{0x51}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(*consensus.BTMAssetID, 1, []byte{0x6b}),
		},
	}),
	types.NewTx(types.TxData{
		SerializedSize: 150,
		TimeRange:      0,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, bc.NewHash([32]byte{0x01}), *consensus.BTMAssetID, 1, 1, []byte{0x51}),
			types.NewSpendInput(nil, bc.NewHash([32]byte{0x02}), bc.NewAssetID([32]byte{0xa1}), 4, 1, []byte{0x51}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(*consensus.BTMAssetID, 1, []byte{0x6b}),
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 4, []byte{0x61}),
		},
	}),
	types.NewTx(types.TxData{
		SerializedSize: 100,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, testutil.MustDecodeHash("dbea684b5c5153ed7729669a53d6c59574f26015a3e1eb2a0e8a1c645425a764"), bc.NewAssetID([32]byte{0xa1}), 4, 1, []byte{0x61}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 3, []byte{0x62}),
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 1, []byte{0x63}),
		},
	}),
	types.NewTx(types.TxData{
		SerializedSize: 100,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, testutil.MustDecodeHash("d84d0be0fd08e7341f2d127749bb0d0844d4560f53bd54861cee9981fd922cad"), bc.NewAssetID([32]byte{0xa1}), 3, 0, []byte{0x62}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 2, []byte{0x64}),
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 1, []byte{0x65}),
		},
	}),
	types.NewTx(types.TxData{
		SerializedSize: 100,
		Inputs: []*types.TxInput{
			types.NewSpendInput(nil, testutil.MustDecodeHash("dbea684b5c5153ed7729669a53d6c59574f26015a3e1eb2a0e8a1c645425a764"), bc.NewAssetID([32]byte{0xa1}), 4, 1, []byte{0x61}),
		},
		Outputs: []*types.TxOutput{
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 3, []byte{0x62}),
			types.NewTxOutput(bc.NewAssetID([32]byte{0xa1}), 1, []byte{0x63}),
		},
	}),
}

type mockStore struct{}

func (s *mockStore) BlockExist(hash *bc.Hash) bool                                { return false }
func (s *mockStore) GetBlock(*bc.Hash) (*types.Block, error)                      { return nil, nil }
func (s *mockStore) GetStoreStatus() *BlockStoreState                             { return nil }
func (s *mockStore) GetTransactionStatus(*bc.Hash) (*bc.TransactionStatus, error) { return nil, nil }
func (s *mockStore) GetTransactionsUtxo(*state.UtxoViewpoint, []*bc.Tx) error     { return nil }
func (s *mockStore) GetUtxo(*bc.Hash) (*storage.UtxoEntry, error)                 { return nil, nil }
func (s *mockStore) LoadBlockIndex(uint64) (*state.BlockIndex, error)             { return nil, nil }
func (s *mockStore) SaveBlock(*types.Block, *bc.TransactionStatus) error          { return nil }
func (s *mockStore) SaveChainStatus(*state.BlockNode, *state.UtxoViewpoint) error { return nil }

func TestAddOrphan(t *testing.T) {
	cases := []struct {
		before         *TxPool
		after          *TxPool
		addOrphan      *TxDesc
		requireParents []*bc.Hash
	}{
		{
			before: &TxPool{
				orphans:       map[bc.Hash]*orphanTx{},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{},
			},
			after: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
					},
				},
			},
			addOrphan:      &TxDesc{Tx: testTxs[0]},
			requireParents: []*bc.Hash{&testTxs[0].SpentOutputIDs[0]},
		},
		{
			before: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
					},
				},
			},
			after: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
					testTxs[1].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[1],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
						testTxs[1].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[1],
							},
						},
					},
				},
			},
			addOrphan:      &TxDesc{Tx: testTxs[1]},
			requireParents: []*bc.Hash{&testTxs[1].SpentOutputIDs[0]},
		},
		{
			before: &TxPool{
				orphans:       map[bc.Hash]*orphanTx{},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{},
			},
			after: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[2].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[2],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[2].SpentOutputIDs[1]: {
						testTxs[2].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[2],
							},
						},
					},
				},
			},
			addOrphan:      &TxDesc{Tx: testTxs[2]},
			requireParents: []*bc.Hash{&testTxs[2].SpentOutputIDs[1]},
		},
	}

	for i, c := range cases {
		c.before.addOrphan(c.addOrphan, c.requireParents)
		for _, orphan := range c.before.orphans {
			orphan.expiration = time.Time{}
		}
		for _, orphans := range c.before.orphansByPrev {
			for _, orphan := range orphans {
				orphan.expiration = time.Time{}
			}
		}
		if !testutil.DeepEqual(c.before, c.after) {
			t.Errorf("case %d: got %v want %v", i, c.before, c.after)
		}
	}
}

func TestAddTransaction(t *testing.T) {
	dispatcher := event.NewDispatcher()
	cases := []struct {
		before *TxPool
		after  *TxPool
		addTx  *TxDesc
	}{
		{
			before: &TxPool{
				pool:            map[bc.Hash]*TxDesc{},
				utxo:            map[bc.Hash]*types.Tx{},
				eventDispatcher: dispatcher,
			},
			after: &TxPool{
				pool: map[bc.Hash]*TxDesc{
					testTxs[2].ID: {
						Tx:         testTxs[2],
						StatusFail: false,
					},
				},
				utxo: map[bc.Hash]*types.Tx{
					*testTxs[2].ResultIds[0]: testTxs[2],
					*testTxs[2].ResultIds[1]: testTxs[2],
				},
			},
			addTx: &TxDesc{
				Tx:         testTxs[2],
				StatusFail: false,
			},
		},
		{
			before: &TxPool{
				pool:            map[bc.Hash]*TxDesc{},
				utxo:            map[bc.Hash]*types.Tx{},
				eventDispatcher: dispatcher,
			},
			after: &TxPool{
				pool: map[bc.Hash]*TxDesc{
					testTxs[2].ID: {
						Tx:         testTxs[2],
						StatusFail: true,
					},
				},
				utxo: map[bc.Hash]*types.Tx{
					*testTxs[2].ResultIds[0]: testTxs[2],
				},
			},
			addTx: &TxDesc{
				Tx:         testTxs[2],
				StatusFail: true,
			},
		},
	}

	for i, c := range cases {
		c.before.addTransaction(c.addTx)
		for _, txD := range c.before.pool {
			txD.Added = time.Time{}
		}
		if !testutil.DeepEqual(c.before.pool, c.after.pool) {
			t.Errorf("case %d: got %v want %v", i, c.before.pool, c.after.pool)
		}
		if !testutil.DeepEqual(c.before.utxo, c.after.utxo) {
			t.Errorf("case %d: got %v want %v", i, c.before.utxo, c.after.utxo)
		}
	}
}

func TestExpireOrphan(t *testing.T) {
	before := &TxPool{
		orphans: map[bc.Hash]*orphanTx{
			testTxs[0].ID: {
				expiration: time.Unix(1533489701, 0),
				TxDesc: &TxDesc{
					Tx: testTxs[0],
				},
			},
			testTxs[1].ID: {
				expiration: time.Unix(1633489701, 0),
				TxDesc: &TxDesc{
					Tx: testTxs[1],
				},
			},
		},
		orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
			testTxs[0].SpentOutputIDs[0]: {
				testTxs[0].ID: {
					expiration: time.Unix(1533489701, 0),
					TxDesc: &TxDesc{
						Tx: testTxs[0],
					},
				},
				testTxs[1].ID: {
					expiration: time.Unix(1633489701, 0),
					TxDesc: &TxDesc{
						Tx: testTxs[1],
					},
				},
			},
		},
	}

	want := &TxPool{
		orphans: map[bc.Hash]*orphanTx{
			testTxs[1].ID: {
				expiration: time.Unix(1633489701, 0),
				TxDesc: &TxDesc{
					Tx: testTxs[1],
				},
			},
		},
		orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
			testTxs[0].SpentOutputIDs[0]: {
				testTxs[1].ID: {
					expiration: time.Unix(1633489701, 0),
					TxDesc: &TxDesc{
						Tx: testTxs[1],
					},
				},
			},
		},
	}

	before.ExpireOrphan(time.Unix(1633479701, 0))
	if !testutil.DeepEqual(before, want) {
		t.Errorf("got %v want %v", before, want)
	}
}

func TestProcessOrphans(t *testing.T) {
	dispatcher := event.NewDispatcher()
	cases := []struct {
		before    *TxPool
		after     *TxPool
		processTx *TxDesc
	}{
		{
			before: &TxPool{
				pool:            map[bc.Hash]*TxDesc{},
				utxo:            map[bc.Hash]*types.Tx{},
				eventDispatcher: dispatcher,
				orphans: map[bc.Hash]*orphanTx{
					testTxs[3].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[3],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[3].SpentOutputIDs[0]: {
						testTxs[3].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[3],
							},
						},
					},
				},
			},
			after: &TxPool{
				pool: map[bc.Hash]*TxDesc{
					testTxs[3].ID: {
						Tx:         testTxs[3],
						StatusFail: false,
					},
				},
				utxo: map[bc.Hash]*types.Tx{
					*testTxs[3].ResultIds[0]: testTxs[3],
					*testTxs[3].ResultIds[1]: testTxs[3],
				},
				eventDispatcher: dispatcher,
				orphans:         map[bc.Hash]*orphanTx{},
				orphansByPrev:   map[bc.Hash]map[bc.Hash]*orphanTx{},
			},
			processTx: &TxDesc{Tx: testTxs[2]},
		},
		{
			before: &TxPool{
				pool:            map[bc.Hash]*TxDesc{},
				utxo:            map[bc.Hash]*types.Tx{},
				eventDispatcher: dispatcher,
				orphans: map[bc.Hash]*orphanTx{
					testTxs[3].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[3],
						},
					},
					testTxs[4].ID: {
						TxDesc: &TxDesc{
							Tx: testTxs[4],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[3].SpentOutputIDs[0]: {
						testTxs[3].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[3],
							},
						},
					},
					testTxs[4].SpentOutputIDs[0]: {
						testTxs[4].ID: {
							TxDesc: &TxDesc{
								Tx: testTxs[4],
							},
						},
					},
				},
			},
			after: &TxPool{
				pool: map[bc.Hash]*TxDesc{
					testTxs[3].ID: {
						Tx:         testTxs[3],
						StatusFail: false,
					},
					testTxs[4].ID: {
						Tx:         testTxs[4],
						StatusFail: false,
					},
				},
				utxo: map[bc.Hash]*types.Tx{
					*testTxs[3].ResultIds[0]: testTxs[3],
					*testTxs[3].ResultIds[1]: testTxs[3],
					*testTxs[4].ResultIds[0]: testTxs[4],
					*testTxs[4].ResultIds[1]: testTxs[4],
				},
				eventDispatcher: dispatcher,
				orphans:         map[bc.Hash]*orphanTx{},
				orphansByPrev:   map[bc.Hash]map[bc.Hash]*orphanTx{},
			},
			processTx: &TxDesc{Tx: testTxs[2]},
		},
	}

	for i, c := range cases {
		c.before.store = &mockStore{}
		c.before.addTransaction(c.processTx)
		c.before.processOrphans(c.processTx)
		c.before.RemoveTransaction(&c.processTx.Tx.ID)
		c.before.store = nil
		c.before.lastUpdated = 0
		for _, txD := range c.before.pool {
			txD.Added = time.Time{}
		}

		if !testutil.DeepEqual(c.before, c.after) {
			t.Errorf("case %d: got %v want %v", i, c.before, c.after)
		}
	}
}

func TestRemoveOrphan(t *testing.T) {
	cases := []struct {
		before       *TxPool
		after        *TxPool
		removeHashes []*bc.Hash
	}{
		{
			before: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						expiration: time.Unix(1533489701, 0),
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							expiration: time.Unix(1533489701, 0),
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
					},
				},
			},
			after: &TxPool{
				orphans:       map[bc.Hash]*orphanTx{},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{},
			},
			removeHashes: []*bc.Hash{
				&testTxs[0].ID,
			},
		},
		{
			before: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						expiration: time.Unix(1533489701, 0),
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
					testTxs[1].ID: {
						expiration: time.Unix(1533489701, 0),
						TxDesc: &TxDesc{
							Tx: testTxs[1],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							expiration: time.Unix(1533489701, 0),
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
						testTxs[1].ID: {
							expiration: time.Unix(1533489701, 0),
							TxDesc: &TxDesc{
								Tx: testTxs[1],
							},
						},
					},
				},
			},
			after: &TxPool{
				orphans: map[bc.Hash]*orphanTx{
					testTxs[0].ID: {
						expiration: time.Unix(1533489701, 0),
						TxDesc: &TxDesc{
							Tx: testTxs[0],
						},
					},
				},
				orphansByPrev: map[bc.Hash]map[bc.Hash]*orphanTx{
					testTxs[0].SpentOutputIDs[0]: {
						testTxs[0].ID: {
							expiration: time.Unix(1533489701, 0),
							TxDesc: &TxDesc{
								Tx: testTxs[0],
							},
						},
					},
				},
			},
			removeHashes: []*bc.Hash{
				&testTxs[1].ID,
			},
		},
	}

	for i, c := range cases {
		for _, hash := range c.removeHashes {
			c.before.removeOrphan(hash)
		}
		if !testutil.DeepEqual(c.before, c.after) {
			t.Errorf("case %d: got %v want %v", i, c.before, c.after)
		}
	}
}

func mockValidateTxOK(tx *bc.Tx, block *bc.Block) (*validation.GasState, error) {
	return &validation.GasState{
		GasValid: true,
	}, nil
}

var errMockValidateErr = errors.New("transaction validate error")

func mockValidateTxErr(tx *bc.Tx, block *bc.Block) (*validation.GasState, error) {
	return &validation.GasState{
		GasValid: true,
	}, errMockValidateErr
}

func mockValidateTxGasInvalid(tx *bc.Tx, block *bc.Block) (*validation.GasState, error) {
	return &validation.GasState{
		GasValid: false,
	}, nil
}

func TestValidateTx(t *testing.T) {
	txpool := &TxPool{
		pool:            map[bc.Hash]*TxDesc{},
		store:           &mockStore{},
		orphans:         map[bc.Hash]*orphanTx{},
		orphansByPrev:   map[bc.Hash]map[bc.Hash]*orphanTx{},
		utxo:            map[bc.Hash]*types.Tx{},
		errCache:        lru.New(maxCachedErrTxs),
		eventDispatcher: event.NewDispatcher(),
	}

	cases := []struct {
		processTx *TxDesc
		ValidateTx
		wantErr error
	}{
		{
			processTx:  &TxDesc{Tx: testTxs[2]},
			ValidateTx: mockValidateTxOK,
			wantErr:    nil,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[2]},
			ValidateTx: mockValidateTxErr,
			wantErr:    errMockValidateErr,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[2]},
			ValidateTx: mockValidateTxOK,
			wantErr:    errMockValidateErr,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[1]},
			ValidateTx: mockValidateTxGasInvalid,
			wantErr:    errGasInvalid,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[1]},
			ValidateTx: mockValidateTxOK,
			wantErr:    errGasInvalid,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[5]},
			ValidateTx: mockValidateTxOK,
			wantErr:    errNoBtmInput,
		},
		{
			processTx:  &TxDesc{Tx: testTxs[5]},
			ValidateTx: mockValidateTxOK,
			wantErr:    errNoBtmInput,
		},
	}

	for i, c := range cases {
		_, err := txpool.ProcessTx(c.ValidateTx, c.processTx.Tx, &types.BlockHeader{Height: 0})
		if err != c.wantErr {
			t.Fatal("test txpool validateTx case:", i, "test error.", "want:", c.wantErr, "got:", err)
		}
	}
}
