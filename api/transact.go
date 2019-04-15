package api

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bytom/account"
	"github.com/bytom/blockchain/txbuilder"
	"github.com/bytom/consensus"
	"github.com/bytom/consensus/segwit"
	"github.com/bytom/errors"
	"github.com/bytom/net/http/reqid"
	"github.com/bytom/protocol/bc"
	"github.com/bytom/protocol/bc/types"
)

var (
	defaultTxTTL    = 30 * time.Minute
	defaultBaseRate = float64(100000)
)

func (a *API) actionDecoder(action string) (func([]byte) (txbuilder.Action, error), bool) {
	decoders := map[string]func([]byte) (txbuilder.Action, error){
		"control_address":              txbuilder.DecodeControlAddressAction,
		"control_program":              txbuilder.DecodeControlProgramAction,
		"issue":                        a.wallet.AssetReg.DecodeIssueAction,
		"retire":                       txbuilder.DecodeRetireAction,
		"spend_account":                a.wallet.AccountMgr.DecodeSpendAction,
		"spend_account_unspent_output": a.wallet.AccountMgr.DecodeSpendUTXOAction,
	}
	decoder, ok := decoders[action]
	return decoder, ok
}

func onlyHaveInputActions(req *BuildRequest) (bool, error) {
	count := 0
	for i, act := range req.Actions {
		actionType, ok := act["type"].(string)
		if !ok {
			return false, errors.WithDetailf(ErrBadActionType, "no action type provided on action %d", i)
		}

		if strings.HasPrefix(actionType, "spend") || actionType == "issue" {
			count++
		}
	}

	return count == len(req.Actions), nil
}

func (a *API) buildSingle(ctx context.Context, req *BuildRequest) (*txbuilder.Template, error) {
	if err := a.checkRequestValidity(ctx, req); err != nil {
		return nil, err
	}
	actions, err := a.mergeSpendActions(req)
	if err != nil {
		return nil, err
	}

	maxTime := time.Now().Add(req.TTL.Duration)
	tpl, err := txbuilder.Build(ctx, req.Tx, actions, maxTime, req.TimeRange)
	if errors.Root(err) == txbuilder.ErrAction {
		// append each of the inner errors contained in the data.
		var Errs string
		var rootErr error
		for i, innerErr := range errors.Data(err)["actions"].([]error) {
			if i == 0 {
				rootErr = errors.Root(innerErr)
			}
			Errs = Errs + innerErr.Error()
		}
		err = errors.WithDetail(rootErr, Errs)
	}
	if err != nil {
		return nil, err
	}

	// ensure null is never returned for signing instructions
	if tpl.SigningInstructions == nil {
		tpl.SigningInstructions = []*txbuilder.SigningInstruction{}
	}
	return tpl, nil
}

// POST /build-transaction
func (a *API) build(ctx context.Context, buildReqs *BuildRequest) Response {
	subctx := reqid.NewSubContext(ctx, reqid.New())
	tmpl, err := a.buildSingle(subctx, buildReqs)
	if err != nil {
		return NewErrorResponse(err)
	}

	return NewSuccessResponse(tmpl)
}
func (a *API) checkRequestValidity(ctx context.Context, req *BuildRequest) error {
	if err := a.completeMissingIDs(ctx, req); err != nil {
		return err
	}

	if req.TTL.Duration == 0 {
		req.TTL.Duration = defaultTxTTL
	}

	if ok, err := onlyHaveInputActions(req); err != nil {
		return err
	} else if ok {
		return errors.WithDetail(ErrBadActionConstruction, "transaction contains only input actions and no output actions")
	}
	return nil
}

func (a *API) mergeSpendActions(req *BuildRequest) ([]txbuilder.Action, error) {
	actions := make([]txbuilder.Action, 0, len(req.Actions))
	for i, act := range req.Actions {
		typ, ok := act["type"].(string)
		if !ok {
			return nil, errors.WithDetailf(ErrBadActionType, "no action type provided on action %d", i)
		}
		decoder, ok := a.actionDecoder(typ)
		if !ok {
			return nil, errors.WithDetailf(ErrBadActionType, "unknown action type %q on action %d", typ, i)
		}

		// Remarshal to JSON, the action may have been modified when we
		// filtered aliases.
		b, err := json.Marshal(act)
		if err != nil {
			return nil, err
		}
		action, err := decoder(b)
		if err != nil {
			return nil, errors.WithDetailf(ErrBadAction, "%s on action %d", err.Error(), i)
		}
		actions = append(actions, action)
	}
	actions = account.MergeSpendAction(actions)
	return actions, nil
}

func (a *API) buildTxs(ctx context.Context, req *BuildRequest) ([]*txbuilder.Template, error) {
	if err := a.checkRequestValidity(ctx, req); err != nil {
		return nil, err
	}
	actions, err := a.mergeSpendActions(req)
	if err != nil {
		return nil, err
	}

	builder := txbuilder.NewBuilder(time.Now().Add(req.TTL.Duration))
	tpls := []*txbuilder.Template{}
	for _, action := range actions {
		if action.ActionType() == "spend_account" {
			tpls, err = account.SpendAccountChain(ctx, builder, action)
		} else {
			err = action.Build(ctx, builder)
		}

		if err != nil {
			builder.Rollback()
			return nil, err
		}
	}

	tpl, _, err := builder.Build()
	if err != nil {
		builder.Rollback()
		return nil, err
	}

	tpls = append(tpls, tpl)
	return tpls, nil
}

// POST /build-chain-transactions
func (a *API) buildChainTxs(ctx context.Context, buildReqs *BuildRequest) Response {
	subctx := reqid.NewSubContext(ctx, reqid.New())
	tmpls, err := a.buildTxs(subctx, buildReqs)
	if err != nil {
		return NewErrorResponse(err)
	}
	return NewSuccessResponse(tmpls)
}

type submitTxResp struct {
	TxID *bc.Hash `json:"tx_id"`
}

// POST /submit-transaction
func (a *API) submit(ctx context.Context, ins struct {
	Tx types.Tx `json:"raw_transaction"`
}) Response {
	if err := txbuilder.FinalizeTx(ctx, a.chain, &ins.Tx); err != nil {
		return NewErrorResponse(err)
	}

	log.WithField("tx_id", ins.Tx.ID.String()).Info("submit single tx")
	return NewSuccessResponse(&submitTxResp{TxID: &ins.Tx.ID})
}

type submitTxsResp struct {
	TxID []*bc.Hash `json:"tx_id"`
}

// POST /submit-transactions
func (a *API) submitTxs(ctx context.Context, ins struct {
	Tx []types.Tx `json:"raw_transactions"`
}) Response {
	txHashs := []*bc.Hash{}
	for i := range ins.Tx {
		if err := txbuilder.FinalizeTx(ctx, a.chain, &ins.Tx[i]); err != nil {
			return NewErrorResponse(err)
		}
		log.WithField("tx_id", ins.Tx[i].ID.String()).Info("submit single tx")
		txHashs = append(txHashs, &ins.Tx[i].ID)
	}
	return NewSuccessResponse(&submitTxsResp{TxID: txHashs})
}

// EstimateTxGasResp estimate transaction consumed gas
type EstimateTxGasResp struct {
	TotalNeu    int64 `json:"total_neu"`
	FlexibleNeu int64 `json:"flexible_neu"`
	StorageNeu  int64 `json:"storage_neu"`
	VMNeu       int64 `json:"vm_neu"`
}

// estimateTxGas estimate consumed neu for transaction
func estimateTxGas(template txbuilder.Template) (*EstimateTxGasResp, error) {
	var baseP2WSHSize, totalWitnessSize, baseP2WSHGas, totalP2WPKHGas, totalP2WSHGas int64
	baseSize := int64(352) // inputSize(224) + outputSize(128)
	baseP2WPKHSize := int64(196)
	baseP2WPKHGas := int64(1409)
	for pos, input := range template.Transaction.TxData.Inputs {
		controlProgram := input.ControlProgram()
		if segwit.IsP2WPKHScript(controlProgram) {
			totalWitnessSize += baseP2WPKHSize
			totalP2WPKHGas += baseP2WPKHGas
		} else if segwit.IsP2WSHScript(controlProgram) {
			baseP2WSHSize, baseP2WSHGas = estimateP2WSHGas(template.SigningInstructions[pos])
			totalWitnessSize += baseP2WSHSize
			totalP2WSHGas += baseP2WSHGas
		}
	}

	totalTxSizeGas := (int64(template.Transaction.TxData.SerializedSize) + totalWitnessSize) * consensus.StorageGasRate
	flexibleGas := int64(0)
	if totalP2WPKHGas > 0 {
		flexibleGas += baseP2WPKHGas + (baseSize+baseP2WPKHSize)*consensus.StorageGasRate
	} else if totalP2WSHGas > 0 {
		flexibleGas += baseP2WSHGas + (baseSize+baseP2WSHSize)*consensus.StorageGasRate
	}

	// the total transaction gas is composed of storage and virtual machines
	totalGas := totalTxSizeGas + totalP2WPKHGas + totalP2WSHGas + flexibleGas
	return &EstimateTxGasResp{
		TotalNeu:    totalGas * consensus.VMGasRate,
		FlexibleNeu: flexibleGas * consensus.VMGasRate,
		StorageNeu:  totalTxSizeGas * consensus.VMGasRate,
		VMNeu:       (totalP2WPKHGas + totalP2WSHGas) * consensus.VMGasRate,
	}, nil
}

// estimateP2WSH return the witness size and the gas consumed to execute the virtual machine for P2WSH program
func estimateP2WSHGas(sigInst *txbuilder.SigningInstruction) (int64, int64) {
	var witnessSize, gas int64
	for _, witness := range sigInst.WitnessComponents {
		switch t := witness.(type) {
		case *txbuilder.SignatureWitness:
			witnessSize += 66*int64(len(t.Keys)) + 130*int64(t.Quorum)
			gas += 1131*int64(len(t.Keys)) + 72*int64(t.Quorum) + 659
			if int64(len(t.Keys)) == 1 && int64(t.Quorum) == 1 {
				gas += 27
			}
		case *txbuilder.RawTxSigWitness:
			witnessSize += 66*int64(len(t.Keys)) + 130*int64(t.Quorum)
			gas += 1131*int64(len(t.Keys)) + 72*int64(t.Quorum) + 659
			if int64(len(t.Keys)) == 1 && int64(t.Quorum) == 1 {
				gas += 27
			}
		}
	}
	return witnessSize, gas
}

// POST /estimate-transaction-gas
func (a *API) estimateTxGas(ctx context.Context, in struct {
	TxTemplate txbuilder.Template `json:"transaction_template"`
}) Response {
	txGasResp, err := estimateTxGas(in.TxTemplate)
	if err != nil {
		return NewErrorResponse(err)
	}
	return NewSuccessResponse(txGasResp)
}
