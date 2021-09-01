package contract

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/google/uuid"

	"golang.org/x/crypto/sha3"

	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/protocol/bc/types"
)

type Instance struct {
	TraceID   string
	UTXOs     []*UTXO
	Finalized bool
	InSync    bool
}

func NewInstance(inUTXOs, outUTXOs []*UTXO) *Instance {
	inst := &Instance{
		TraceID:   uuid.New().String(),
		UTXOs:     outUTXOs,
		Finalized: len(outUTXOs) == 0,
	}
	if inst.Finalized {
		inst.UTXOs = inUTXOs
	}
	return inst
}

type InstanceTable struct {
	traceIdToInst  map[string]*Instance
	utxoHashToInst map[string]*Instance
}

func NewInstanceTable() *InstanceTable {
	return &InstanceTable{
		traceIdToInst:  make(map[string]*Instance),
		utxoHashToInst: make(map[string]*Instance),
	}
}

func (i *InstanceTable) GetByID(id string) *Instance {
	return i.traceIdToInst[id]
}

func (i *InstanceTable) GetByUTXOs(utxos []*UTXO) *Instance {
	return i.utxoHashToInst[utxoKey(utxos)]
}

func (i *InstanceTable) Put(instance *Instance) {
	i.traceIdToInst[instance.TraceID] = instance
	i.utxoHashToInst[utxoKey(instance.UTXOs)] = instance
	// TODO must remove prev key of utxos
}

func (i *InstanceTable) Remove(id string) {
	if inst, ok := i.traceIdToInst[id]; ok {
		delete(i.traceIdToInst, id)
		delete(i.utxoHashToInst, utxoKey(inst.UTXOs))
	}
}

type UTXO struct {
	assetID   bc.AssetID
	sourceID  uint64
	sourcePos uint64
	stateData []byte
	amount    uint64
	hash      bc.Hash
	program   []byte
}

func inputToUTXO(input *types.TxInput) *UTXO {
	outputID, _ := input.SpentOutputID()
	return &UTXO{
		assetID: input.AssetID(),
		amount:  input.Amount(),
		hash:    outputID,
		program: input.ControlProgram(),
	}
}

func outputToUTXO(output *types.TxOutput, outputID bc.Hash) *UTXO {
	return &UTXO{
		assetID: *output.AssetId,
		amount:  output.Amount,
		hash:    outputID,
		program: output.ControlProgram,
	}
}

func utxoKey(utxos []*UTXO) string {
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].hash.String() < utxos[j].hash.String()
	})

	buff := new(bytes.Buffer)
	for _, u := range utxos {
		buff.Write(u.hash.Bytes())
	}
	digest := sha3.Sum256(buff.Bytes())
	return hex.EncodeToString(digest[:])
}
