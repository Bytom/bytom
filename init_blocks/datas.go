package initblocks

import (
	"encoding/json"
)

const (
	OutputCntPerTx = 100
	TxCntPerBlock  = 100
)

// AddressBalance address and balance
type AddressBalance struct {
	ControlProgram string
	Balance        uint64
}

//RawBalance raw balance from file
type RawBalance struct {
	ControlProgram string `json:"AddressScript"`
	Asset          string `json:"Asset"`
	Balance        uint64 `json:"Balance"`
}

type assetTotal struct {
	Asset  string
	Amount uint64
}

func sumAddressBalances(addressBalances []AddressBalance) uint64 {
	sum := uint64(0)
	for _, addressBalance := range addressBalances {
		sum += addressBalance.Balance
	}
	return sum
}

func calcAssetTotals(asset2distributions map[string][]AddressBalance) []assetTotal {
	var assetTotals []assetTotal
	for asset, balances := range asset2distributions {
		assetTotals = append(assetTotals, assetTotal{
			Asset:  asset,
			Amount: sumAddressBalances(balances),
		})
	}

	return assetTotals
}

func mapAssetDistributions(file string) (map[string][]AddressBalance, error) {
	lines, err := ReadFileLines(file)
	if err != nil {
		return nil, err
	}

	var asset2distributions = map[string][]AddressBalance{}
	for _, line := range lines {
		raw := new(RawBalance)
		if err := json.Unmarshal([]byte(line), raw); err != nil {
			return nil, err
		}

		asset2distributions[raw.Asset] = append(asset2distributions[raw.Asset],
			AddressBalance{
				ControlProgram: raw.ControlProgram,
				Balance:        raw.Balance,
			})
	}
	return asset2distributions, nil
}
