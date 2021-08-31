package contract

import (
	"github.com/bytom/bytom/protocol/bc"
)

type TraceService interface {
	CreateNewInstance(txHash, blockHash bc.Hash) (string, error)

	RemoveInstance(traceID string) error

	GetInstance(traceID string) (*Instance, error)
}
