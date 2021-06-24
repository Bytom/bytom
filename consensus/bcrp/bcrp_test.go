package bcrp

import (
	"encoding/hex"
	"testing"
)

func TestIsBCRPScript(t *testing.T) {
	tests := []struct {
		program  string
		expected bool
	}{
		{
			program:  "",
			expected: false,
		},
		{
			program:  "ae20ac20f5cdb9ada2ae9836bcfff32126d6b885aa3f73ee111a95d1bf37f3904aca5151ad",
			expected: false,
		},
		{
			program:  "694c04626372704c01014c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0",
			expected: false,
		},
		{
			program:  "6a4c04424352504c01014c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0",
			expected: false,
		},
		{
			program:  "6a4c04626372704c01024c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0",
			expected: false,
		},

		{
			program:  "6a046263727001012820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0",
			expected: true,
		},
	}

	for i, test := range tests {
		program, err := hex.DecodeString(test.program)
		if err != nil {
			t.Fatal(err)
		}

		expected := IsBCRPScript(program)
		if expected != test.expected {
			t.Errorf("TestIsTemplateRegister #%d failed: got %v want %v", i, expected, test.expected)
		}
	}
}

func TestIsCallContractScript(t *testing.T) {
	tests := []struct {
		program  string
		expected bool
	}{
		{
			program:  "",
			expected: false,
		},
		{
			program:  "6a4c04626372704c01014c2820e9108d3ca8049800727f6a3505b3a2710dc579405dde03c250f16d9a7e1e6e787403ae7cac00c0",
			expected: false,
		},
		{
			program:  "00204e4f02d43bf50171f7f25d046b7f016002da410fc00d2e8902e7b170c98cf946",
			expected: false,
		},
		{
			program:  "51204e4f02d43bf50171f7f25d046b7f016002da410fc00d2e8902e7b170c98cf946",
			expected: false,
		},
		{
			program:  "0462637270204e4f02d43bf50171f7f25d046b7f016002da410fc00d2e8902e7b170c98cf946",
			expected: true,
		},
	}

	for i, test := range tests {
		program, err := hex.DecodeString(test.program)
		if err != nil {
			t.Fatal(err)
		}

		expected := IsCallContractScript(program)
		if expected != test.expected {
			t.Errorf("TestIsCallContractScript #%d failed: got %v want %v", i, expected, test.expected)
		}
	}
}

func TestParseContractHash(t *testing.T) {
	tests := []struct {
		program  string
		expected string
	}{
		{
			//call BCRP script format: OP_1 + OP_DATA_32 + SHA3-256(contract)
			program:  "5120605f9b8e978bb3956d729047e556cdf4b56238348d4293ad9afef376462063c5",
			expected: "605f9b8e978bb3956d729047e556cdf4b56238348d4293ad9afef376462063c5",
		},
	}

	for i, test := range tests {
		program, err := hex.DecodeString(test.program)
		if err != nil {
			t.Fatal(err)
		}

		hash, err := ParseContractHash(program)
		if err != nil {
			t.Fatal(err)
		}

		expected := hex.EncodeToString(hash[:])
		if expected != test.expected {
			t.Errorf("TestParseContractHash #%d failed: got %v want %v", i, expected, test.expected)
		}
	}
}
