package bcrp

import (
	"bytes"

	"github.com/bytom/bytom/consensus"
	"github.com/bytom/bytom/errors"
	"github.com/bytom/bytom/protocol/vm"
)

// BCRP bytom contract register protocol
const BCRP = "bcrp"

// Version bcrp version
const Version = 1

// IsBCRPScript checks if a control program is bytom contract register protocol
// BCRP script format: OP_FAIL + OP_DATA_4 + "bcrp" + OP_DATA_1 + "1" + {{dynamic_op}} + contract
// 0 < len(contract) <= 75       dynamic_op -> OP_DATA_N
// 75 <len(contract) < 256       dynamic_op -> OP_PUSHDATA1
// 256 <= len(contract) < 65536  dynamic_op -> OP_PUSHDATA2
// len(contract) >= 65536        dynamic_op -> OP_PUSHDATA4
func IsBCRPScript(prog []byte) bool {
	inst, err := vm.ParseProgram(prog)
	if err != nil {
		return false
	}

	if len(inst) != 4 {
		return false
	}

	if inst[0].Op != vm.OP_FAIL {
		return false
	}

	if inst[1].Op != vm.OP_DATA_4 || !bytes.Equal(inst[1].Data, []byte(BCRP)) {
		return false
	}

	if inst[2].Op != vm.OP_DATA_1 || !bytes.Equal(inst[2].Data, []byte{byte(Version)}) {
		return false
	}

	if len(inst[3].Data) <= 0 {
		return false
	}

	if len(inst[3].Data) <= 75 && !(inst[3].Op >= vm.OP_DATA_1 && inst[3].Op <= vm.OP_DATA_75) {
		return false
	}

	if len(inst[3].Data) > 75 && len(inst[3].Data) < 1<<8 && inst[3].Op != vm.OP_PUSHDATA1 {
		return false
	}

	if len(inst[3].Data) >= 1<<8 && len(inst[3].Data) < 1<<16 && inst[3].Op != vm.OP_PUSHDATA2 {
		return false
	}

	if len(inst[3].Data) >= 1<<16 && inst[3].Op != vm.OP_PUSHDATA4 {
		return false
	}

	return true
}

// IsCallContractScript checks if a program is script call contract registered by BCRP
// call contract script format: OP_DATA_4 + "bcrp"+ OP_DATA_32 + SHA3-256(contract)
func IsCallContractScript(prog []byte) bool {
	insts, err := vm.ParseProgram(prog)
	if err != nil {
		return false
	}

	if len(insts) != 2 {
		return false
	}

	if insts[0].Op != vm.OP_DATA_4 || !bytes.Equal(insts[0].Data, []byte(BCRP)) {
		return false
	}

	return insts[1].Op == vm.OP_DATA_32 && len(insts[1].Data) == consensus.BCRPContractHashDataSize
}

// ParseContractHash parse contract hash from call BCRP script
// call contract script format: OP_DATA_4 + "bcrp"+ OP_DATA_32 + SHA3-256(contract)
func ParseContractHash(prog []byte) ([32]byte, error) {
	insts, err := vm.ParseProgram(prog)
	if err != nil {
		return [32]byte{}, err
	}

	if len(insts) != 2 {
		return [32]byte{}, errors.New("unsupport program")
	}

	var hash [32]byte
	copy(hash[:], insts[1].Data)

	return hash, nil
}
