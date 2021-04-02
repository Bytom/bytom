package bc

import (
	"reflect"
	"testing"
)

func BenchmarkEntryID(b *testing.B) {
	m := NewMux([]*ValueSource{{Position: 1}}, &Program{Code: []byte{1}, VmVersion: 1})

	entries := []Entry{
		NewIssuance(nil, &AssetAmount{}, 0),
		m,
		NewTxHeader(1, 1, 0, nil),
		NewOutput(&ValueSource{}, &Program{Code: []byte{1}, VmVersion: 1}, &StateData{StateData: []byte{1}}, 0),
		NewRetirement(&ValueSource{}, 1),
		NewSpend(&Hash{}, 0),
	}

	for _, e := range entries {
		name := reflect.TypeOf(e).Elem().Name()
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				EntryID(e)
			}
		})
	}
}

func TestEntryID(t *testing.T) {
	cases := []struct {
		entry         Entry
		expectEntryID string
	}{
		{
			entry:         NewIssuance(&Hash{V0: 0, V1: 1, V2: 2, V3: 3}, &AssetAmount{&AssetID{V0: 1, V1: 2, V2: 3, V3: 4}, 100}, 1),
			expectEntryID: "3012b9b6da3962bb2388cdf5db7f3b93a2b696fcc70e79bc5da1238a6d66ae73",
		},
		{
			entry: NewMux(
				[]*ValueSource{
					{
						Ref:      &Hash{V0: 0, V1: 1, V2: 2, V3: 3},
						Value:    &AssetAmount{&AssetID{V0: 1, V1: 2, V2: 3, V3: 4}, 100},
						Position: 1,
					},
				},
				&Program{VmVersion: 1, Code: []byte{1, 2, 3, 4}},
			),
			expectEntryID: "1be3a2f6d7be260488a31f2fb62d823a10572a70a0fbb8d0e02ad421a39ec2d9",
		},
		{
			entry: NewOutput(
				&ValueSource{
					Ref:      &Hash{V0: 4, V1: 5, V2: 6, V3: 7},
					Value:    &AssetAmount{&AssetID{V0: 1, V1: 1, V2: 1, V3: 1}, 10},
					Position: 10,
				},
				&Program{VmVersion: 1, Code: []byte{5, 5, 5, 5}},
				&StateData{StateData: []byte{3, 4}},
				1,
			),
			expectEntryID: "cb520fa0697ecdbd6380bcd31d0d88f2727f7acf9e5af1fc192074f973e5a840",
		},
		{
			entry: NewRetirement(
				&ValueSource{
					Ref:      &Hash{V0: 4, V1: 5, V2: 6, V3: 7},
					Value:    &AssetAmount{&AssetID{V0: 1, V1: 1, V2: 1, V3: 1}, 10},
					Position: 10,
				},
				1,
			),
			expectEntryID: "538c367f7b6e1e9bf205ed0a29def84a1467c477b19812a6934e831c78c4da62",
		},
		{
			entry:         NewSpend(&Hash{V0: 0, V1: 1, V2: 2, V3: 3}, 1),
			expectEntryID: "2761dbb13967af8944620c134e0f336bbbb26f61eb4ecd154bc034ad6155b9e8",
		},
		{
			entry:         NewTxHeader(1, 100, 1000, []*Hash{&Hash{V0: 4, V1: 5, V2: 6, V3: 7}}),
			expectEntryID: "ba592aa0841bd4649d9a04309e2e8497ac6f295a847cadd9de6b6f9c2d806663",
		},
	}

	for _, c := range cases {
		entryID := EntryID(c.entry)
		if entryID.String() != c.expectEntryID {
			t.Errorf("the got extry id:%s is not equals to expect entry id:%s", entryID.String(), c.expectEntryID)
		}
	}
}
