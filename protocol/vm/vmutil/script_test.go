package vmutil

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bytom/protocol/vm"
)

// TestIsUnspendable ensures the IsUnspendable function returns the expected
// results.
func TestIsUnspendable(t *testing.T) {
	tests := []struct {
		pkScript []byte
		expected bool
	}{
		{
			// Unspendable
			pkScript: []byte{0x6a, 0x04, 0x74, 0x65, 0x73, 0x74},
			expected: true,
		},
		{
			// Spendable
			pkScript: []byte{0x76, 0xa9, 0x14, 0x29, 0x95, 0xa0,
				0xfe, 0x68, 0x43, 0xfa, 0x9b, 0x95, 0x45,
				0x97, 0xf0, 0xdc, 0xa7, 0xa4, 0x4d, 0xf6,
				0xfa, 0x0b, 0x5c, 0x88, 0xac},
			expected: false,
		},
	}

	for i, test := range tests {
		res := IsUnspendable(test.pkScript)
		if res != test.expected {
			t.Errorf("TestIsUnspendable #%d failed: got %v want %v",
				i, res, test.expected)
			continue
		}
	}
}

// Programs that run without error.
func TestProgramOKSm2(t *testing.T) {
	doOKNotOKSm2(t, true)
}

// Programs that return an ErrFalseVMResult.
func TestProgramNotOKSm2(t *testing.T) {
	doOKNotOKSm2(t, false)
}

func doOKNotOKSm2(t *testing.T, expectOK bool) {
	cases := []struct {
		prog        []byte
		args        [][]byte
		wantGasLeft int64
		wantErr     error
	}{
		{
			prog: tP2PKHSigSm2Program(decodeString("21b045d0d3fbf8a095a19b3e8c52dc909ca62f32")), // f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640
			args: [][]byte{
				// decodeString("f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640"),
				decodeString("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3" + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"),
				decodeString("01" + "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"),
			},
			wantGasLeft: 98590,
		},
	}
	for i, c := range cases {
		context := new(vm.Context)
		context.Code = c.prog
		context.Arguments = c.args
		context.VMVersion = 1
		context.TxSigHash = func() []byte { return decodeString("f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640") }
		gasLimit := int64(100000)

		gasLeft, err := vm.Verify(context, gasLimit)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(i, " : ", gasLeft, " , wantGasLeft is:", c.wantGasLeft)
	}
}

func decodeString(s string) []byte {
	data, _ := hex.DecodeString(s)

	return data
}

func tP2PKHSigSm2Program(pubkeyHash []byte) []byte {
	b, err := P2PKHSigSm2Program(pubkeyHash)
	if err != nil {
		fmt.Println(err)
	}

	return b
}
