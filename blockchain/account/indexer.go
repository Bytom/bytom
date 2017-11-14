package account

import (
	"context"
	"encoding/json"

	log "github.com/sirupsen/logrus"
	"github.com/tendermint/tmlibs/db"

	"github.com/bytom/blockchain/pin"
	"github.com/bytom/blockchain/query"
	"github.com/bytom/blockchain/signers"
	"github.com/bytom/crypto/sha3pool"
	chainjson "github.com/bytom/encoding/json"
	"github.com/bytom/errors"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/legacy"
)

const (
	// InsertUnspentsPinName is used to identify the pin associated with
	// the account indexer block processor.
	InsertUnspentsPinName = "insert-account-unspents"
	// DeleteSpentsPinName is used to identify the pin associated
	// with the processor that deletes spent account UTXOs.
	DeleteSpentsPinName = "delete-account-spents"

	AccountUTXOPreFix = "ACU:"
)

func accountUTXOKey(name string) []byte {
	return []byte(AccountUTXOPreFix + name)
}

type AccountUTXOs struct {
	OutputID     []byte
	AssetID      []byte
	Amount       uint64
	AccountID    string
	ProgramIndex uint64
	Program      []byte
	BlockHeight  uint64
	SourceID     []byte
	SourcePos    uint64
	RefData      []byte
	Change       bool
	Spent        bool
}

var emptyJSONObject = json.RawMessage(`{}`)

// A Saver is responsible for saving an annotated account object.
// for indexing and retrieval.
// If the Core is configured not to provide search services,
// SaveAnnotatedAccount can be a no-op.
type Saver interface {
	SaveAnnotatedAccount(context.Context, *query.AnnotatedAccount) error
}

func Annotated(a *Account) (*query.AnnotatedAccount, error) {
	aa := &query.AnnotatedAccount{
		ID:     a.ID,
		Alias:  a.Alias,
		Quorum: a.Quorum,
		Tags:   &emptyJSONObject,
	}

	tags, err := json.Marshal(a.Tags)
	if err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		rawTags := json.RawMessage(tags)
		aa.Tags = &rawTags
	}

	path := signers.Path(a.Signer, signers.AccountKeySpace)
	var jsonPath []chainjson.HexBytes
	for _, p := range path {
		jsonPath = append(jsonPath, p)
	}
	for _, xpub := range a.XPubs {
		aa.Keys = append(aa.Keys, &query.AccountKey{
			RootXPub:              xpub,
			AccountXPub:           xpub.Derive(path),
			AccountDerivationPath: jsonPath,
		})
	}
	return aa, nil
}

func (m *Manager) indexAnnotatedAccount(ctx context.Context, a *Account) error {
	if m.indexer == nil {
		return nil
	}
	aa, err := Annotated(a)
	if err != nil {
		return err
	}
	return m.indexer.SaveAnnotatedAccount(ctx, aa)
}

type rawOutput struct {
	OutputID bc.Hash
	bc.AssetAmount
	ControlProgram []byte
	txHash         bc.Hash
	outputIndex    uint32
	sourceID       bc.Hash
	sourcePos      uint64
	refData        bc.Hash
}

type accountOutput struct {
	rawOutput
	AccountID string
	keyIndex  uint64
	change    bool
}

func (m *Manager) ProcessBlocks() {
	if m.pinStore == nil {
		return
	}

	for {
		select {
		case <-m.pinStore.AllContinue:
			go m.pinStore.ProcessBlocks(m.chain, DeleteSpentsPinName, func(b *legacy.Block) error {
				<-m.pinStore.PinWaiter(InsertUnspentsPinName, b.Height)
				return m.deleteSpentOutputs(b)
			})
			m.pinStore.ProcessBlocks(m.chain, InsertUnspentsPinName, m.indexAccountUTXOs)
		default:
		}
	}
}

func (m *Manager) deleteSpentOutputs(b *legacy.Block) error {
	// Delete consumed account UTXOs.
	var au AccountUTXOs
	var rawDel []byte
	storeBatch := m.pinStore.DB.NewBatch()

	delOutputIDs := prevoutDBKeys(b.Transactions...)
	for _, delOutputID := range delOutputIDs {

		rawDel = m.pinStore.DB.Get(accountUTXOKey(string(delOutputID.Bytes())))
		if rawDel == nil {
			continue
		}

		err := json.Unmarshal(rawDel, &au)
		if err != nil {
			log.WithFields(log.Fields{"delete utxo hash": delOutputID.String(), "error": err}).Error("unmarshal spent utxo fail")
			continue
		}

		au.Spent = true

		rawDel, err = json.Marshal(&au)
		if err != nil {
			log.WithField("delete utxo hash", delOutputID.String()).Error("marshal spent utxo fail")
			continue
		}

		storeBatch.Set(accountUTXOKey(string(delOutputID.Bytes())), rawDel)
	}

	storeBatch.Write()
	return errors.Wrap(nil, "deleting spent account utxos")
}

func (m *Manager) indexAccountUTXOs(b *legacy.Block) error {
	// Upsert any UTXOs belonging to accounts managed by this Core.
	outs := make([]*rawOutput, 0, len(b.Transactions))
	for _, tx := range b.Transactions {
		for j, out := range tx.Outputs {
			resOutID := tx.ResultIds[j]
			resOut, ok := tx.Entries[*resOutID].(*bc.Output)
			if !ok {
				continue
			}
			out := &rawOutput{
				OutputID:       *tx.OutputID(j),
				AssetAmount:    out.AssetAmount,
				ControlProgram: out.ControlProgram,
				txHash:         tx.ID,
				outputIndex:    uint32(j),
				sourceID:       *resOut.Source.Ref,
				sourcePos:      resOut.Source.Position,
				refData:        *resOut.Data,
			}
			outs = append(outs, out)
		}
	}
	accOuts := m.loadAccountInfo(outs)

	err := m.upsertConfirmedAccountOutputs(accOuts, b)
	return errors.Wrap(err, "upserting confirmed account utxos")
}

func ReverseAccountUTXOs(s *pin.Store, batch *db.Batch, b *legacy.Block) {
	var au AccountUTXOs
	var rawDel []byte

	//handle spent UTXOs
	delOutputIDs := prevoutDBKeys(b.Transactions...)
	for _, delOutputID := range delOutputIDs {

		rawDel = s.DB.Get(accountUTXOKey(string(delOutputID.Bytes())))
		if rawDel == nil {
			continue
		}

		err := json.Unmarshal(rawDel, &au)
		if err != nil {
			log.WithFields(log.Fields{"reverse utxo hash": delOutputID.String(), "error": err}).Error("unmarshal spent utxo fail")
			continue
		}
		// reverse spent
		au.Spent = false

		rawDel, err = json.Marshal(&au)
		if err != nil {
			log.WithField("reverse utxo hash", delOutputID.String()).Error("marshal spent utxo fail")
			continue
		}

		(*batch).Set(accountUTXOKey(string(delOutputID.Bytes())), rawDel)
	}

	//handle new UTXOs
	for _, tx := range b.Transactions {
		for j, _ := range tx.Outputs {
			resOutID := tx.ResultIds[j]
			_, ok := tx.Entries[*resOutID].(*bc.Output)
			if !ok {
				//retirement
				continue
			}
			//delete new UTXOs
			(*batch).Delete(accountUTXOKey(string(resOutID.Bytes())))
		}
	}

}

func prevoutDBKeys(txs ...*legacy.Tx) (outputIDs []bc.Hash) {
	for _, tx := range txs {
		for _, inpID := range tx.Tx.InputIDs {
			if sp, err := tx.Spend(inpID); err == nil {
				outputIDs = append(outputIDs, *sp.SpentOutputId)
			}
		}
	}
	return
}

// loadAccountInfo turns a set of output IDs into a set of
// outputs by adding account annotations.  Outputs that can't be
// annotated are excluded from the result.
func (m *Manager) loadAccountInfo(outs []*rawOutput) []*accountOutput {
	outsByScript := make(map[string][]*rawOutput, len(outs))
	for _, out := range outs {
		scriptStr := string(out.ControlProgram)
		outsByScript[scriptStr] = append(outsByScript[scriptStr], out)
	}

	result := make([]*accountOutput, 0, len(outs))
	cp := controlProgram{}

	var hash []byte
	for s := range outsByScript {
		sha3pool.Sum256(hash, []byte(s))
		bytes := m.db.Get(accountCPKey(string(hash)))
		if bytes == nil {
			continue
		}

		err := json.Unmarshal(bytes, &cp)
		if err != nil {
			continue
		}

		//filte the accounts which exists in accountdb with wallet enabled
		isExist := m.db.Get(accountKey(cp.AccountID))
		if isExist == nil {
			continue
		}

		for _, out := range outsByScript[s] {
			newOut := &accountOutput{
				rawOutput: *out,
				AccountID: cp.AccountID,
				keyIndex:  cp.KeyIndex,
				change:    cp.Change,
			}
			result = append(result, newOut)
		}
	}

	return result
}

// upsertConfirmedAccountOutputs records the account data for confirmed utxos.
// If the account utxo already exists (because it's from a local tx), the
// block confirmation data will in the row will be updated.
func (m *Manager) upsertConfirmedAccountOutputs(outs []*accountOutput, block *legacy.Block) error {
	var au *AccountUTXOs
	storebatch := m.pinStore.DB.NewBatch()

	for _, out := range outs {
		au = &AccountUTXOs{OutputID: out.OutputID.Bytes(),
			AssetID:      out.AssetId.Bytes(),
			Amount:       out.Amount,
			AccountID:    out.AccountID,
			ProgramIndex: out.keyIndex,
			Program:      out.ControlProgram,
			BlockHeight:  block.Height,
			SourceID:     out.sourceID.Bytes(),
			SourcePos:    out.sourcePos,
			RefData:      out.refData.Bytes(),
			Change:       out.change,
			Spent:        false}

		accountutxo, err := json.Marshal(au)
		if err != nil {
			return errors.Wrap(err, "failed marshal accountutxo")
		}

		if len(accountutxo) > 0 {
			storebatch.Set(accountUTXOKey(string(au.OutputID)), accountutxo)
		}

	}

	storebatch.Write()
	return nil
}
