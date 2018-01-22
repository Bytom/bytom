// Code generated by protoc-gen-go. DO NOT EDIT.
// source: bc.proto

/*
Package bc is a generated protocol buffer package.

It is generated from these files:
	bc.proto

It has these top-level messages:
	Hash
	Program
	AssetID
	AssetAmount
	AssetDefinition
	ValueSource
	ValueDestination
	BlockHeader
	TxHeader
	TransactionStatus
	Mux
	Nonce
	Coinbase
	Output
	Retirement
	Issuance
	Spend
*/
package bc

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Hash struct {
	V0 uint64 `protobuf:"fixed64,1,opt,name=v0" json:"v0,omitempty"`
	V1 uint64 `protobuf:"fixed64,2,opt,name=v1" json:"v1,omitempty"`
	V2 uint64 `protobuf:"fixed64,3,opt,name=v2" json:"v2,omitempty"`
	V3 uint64 `protobuf:"fixed64,4,opt,name=v3" json:"v3,omitempty"`
}

func (m *Hash) Reset()                    { *m = Hash{} }
func (m *Hash) String() string            { return proto.CompactTextString(m) }
func (*Hash) ProtoMessage()               {}
func (*Hash) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Hash) GetV0() uint64 {
	if m != nil {
		return m.V0
	}
	return 0
}

func (m *Hash) GetV1() uint64 {
	if m != nil {
		return m.V1
	}
	return 0
}

func (m *Hash) GetV2() uint64 {
	if m != nil {
		return m.V2
	}
	return 0
}

func (m *Hash) GetV3() uint64 {
	if m != nil {
		return m.V3
	}
	return 0
}

type Program struct {
	VmVersion uint64 `protobuf:"varint,1,opt,name=vm_version,json=vmVersion" json:"vm_version,omitempty"`
	Code      []byte `protobuf:"bytes,2,opt,name=code,proto3" json:"code,omitempty"`
}

func (m *Program) Reset()                    { *m = Program{} }
func (m *Program) String() string            { return proto.CompactTextString(m) }
func (*Program) ProtoMessage()               {}
func (*Program) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Program) GetVmVersion() uint64 {
	if m != nil {
		return m.VmVersion
	}
	return 0
}

func (m *Program) GetCode() []byte {
	if m != nil {
		return m.Code
	}
	return nil
}

// This message type duplicates Hash, above. One alternative is to
// embed a Hash inside an AssetID. But it's useful for AssetID to be
// plain old data (without pointers). Another alternative is use Hash
// in any protobuf types where an AssetID is called for, but it's
// preferable to have type safety.
type AssetID struct {
	V0 uint64 `protobuf:"fixed64,1,opt,name=v0" json:"v0,omitempty"`
	V1 uint64 `protobuf:"fixed64,2,opt,name=v1" json:"v1,omitempty"`
	V2 uint64 `protobuf:"fixed64,3,opt,name=v2" json:"v2,omitempty"`
	V3 uint64 `protobuf:"fixed64,4,opt,name=v3" json:"v3,omitempty"`
}

func (m *AssetID) Reset()                    { *m = AssetID{} }
func (m *AssetID) String() string            { return proto.CompactTextString(m) }
func (*AssetID) ProtoMessage()               {}
func (*AssetID) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *AssetID) GetV0() uint64 {
	if m != nil {
		return m.V0
	}
	return 0
}

func (m *AssetID) GetV1() uint64 {
	if m != nil {
		return m.V1
	}
	return 0
}

func (m *AssetID) GetV2() uint64 {
	if m != nil {
		return m.V2
	}
	return 0
}

func (m *AssetID) GetV3() uint64 {
	if m != nil {
		return m.V3
	}
	return 0
}

type AssetAmount struct {
	AssetId *AssetID `protobuf:"bytes,1,opt,name=asset_id,json=assetId" json:"asset_id,omitempty"`
	Amount  uint64   `protobuf:"varint,2,opt,name=amount" json:"amount,omitempty"`
}

func (m *AssetAmount) Reset()                    { *m = AssetAmount{} }
func (m *AssetAmount) String() string            { return proto.CompactTextString(m) }
func (*AssetAmount) ProtoMessage()               {}
func (*AssetAmount) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *AssetAmount) GetAssetId() *AssetID {
	if m != nil {
		return m.AssetId
	}
	return nil
}

func (m *AssetAmount) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

type AssetDefinition struct {
	InitialBlockId  *Hash    `protobuf:"bytes,1,opt,name=initial_block_id,json=initialBlockId" json:"initial_block_id,omitempty"`
	IssuanceProgram *Program `protobuf:"bytes,2,opt,name=issuance_program,json=issuanceProgram" json:"issuance_program,omitempty"`
	Data            *Hash    `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
}

func (m *AssetDefinition) Reset()                    { *m = AssetDefinition{} }
func (m *AssetDefinition) String() string            { return proto.CompactTextString(m) }
func (*AssetDefinition) ProtoMessage()               {}
func (*AssetDefinition) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *AssetDefinition) GetInitialBlockId() *Hash {
	if m != nil {
		return m.InitialBlockId
	}
	return nil
}

func (m *AssetDefinition) GetIssuanceProgram() *Program {
	if m != nil {
		return m.IssuanceProgram
	}
	return nil
}

func (m *AssetDefinition) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

type ValueSource struct {
	Ref      *Hash        `protobuf:"bytes,1,opt,name=ref" json:"ref,omitempty"`
	Value    *AssetAmount `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	Position uint64       `protobuf:"varint,3,opt,name=position" json:"position,omitempty"`
}

func (m *ValueSource) Reset()                    { *m = ValueSource{} }
func (m *ValueSource) String() string            { return proto.CompactTextString(m) }
func (*ValueSource) ProtoMessage()               {}
func (*ValueSource) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ValueSource) GetRef() *Hash {
	if m != nil {
		return m.Ref
	}
	return nil
}

func (m *ValueSource) GetValue() *AssetAmount {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *ValueSource) GetPosition() uint64 {
	if m != nil {
		return m.Position
	}
	return 0
}

type ValueDestination struct {
	Ref      *Hash        `protobuf:"bytes,1,opt,name=ref" json:"ref,omitempty"`
	Value    *AssetAmount `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	Position uint64       `protobuf:"varint,3,opt,name=position" json:"position,omitempty"`
}

func (m *ValueDestination) Reset()                    { *m = ValueDestination{} }
func (m *ValueDestination) String() string            { return proto.CompactTextString(m) }
func (*ValueDestination) ProtoMessage()               {}
func (*ValueDestination) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *ValueDestination) GetRef() *Hash {
	if m != nil {
		return m.Ref
	}
	return nil
}

func (m *ValueDestination) GetValue() *AssetAmount {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *ValueDestination) GetPosition() uint64 {
	if m != nil {
		return m.Position
	}
	return 0
}

type BlockHeader struct {
	Version           uint64             `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	SerializedSize    uint64             `protobuf:"varint,2,opt,name=serialized_size,json=serializedSize" json:"serialized_size,omitempty"`
	Height            uint64             `protobuf:"varint,3,opt,name=height" json:"height,omitempty"`
	PreviousBlockId   *Hash              `protobuf:"bytes,4,opt,name=previous_block_id,json=previousBlockId" json:"previous_block_id,omitempty"`
	Seed              *Hash              `protobuf:"bytes,5,opt,name=seed" json:"seed,omitempty"`
	TimestampMs       uint64             `protobuf:"varint,6,opt,name=timestamp_ms,json=timestampMs" json:"timestamp_ms,omitempty"`
	TransactionsRoot  *Hash              `protobuf:"bytes,7,opt,name=transactions_root,json=transactionsRoot" json:"transactions_root,omitempty"`
	AssetsRoot        *Hash              `protobuf:"bytes,8,opt,name=assets_root,json=assetsRoot" json:"assets_root,omitempty"`
	TransactionStatus *TransactionStatus `protobuf:"bytes,9,opt,name=transaction_status,json=transactionStatus" json:"transaction_status,omitempty"`
	Nonce             uint64             `protobuf:"varint,10,opt,name=nonce" json:"nonce,omitempty"`
	Bits              uint64             `protobuf:"varint,11,opt,name=bits" json:"bits,omitempty"`
}

func (m *BlockHeader) Reset()                    { *m = BlockHeader{} }
func (m *BlockHeader) String() string            { return proto.CompactTextString(m) }
func (*BlockHeader) ProtoMessage()               {}
func (*BlockHeader) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *BlockHeader) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *BlockHeader) GetSerializedSize() uint64 {
	if m != nil {
		return m.SerializedSize
	}
	return 0
}

func (m *BlockHeader) GetHeight() uint64 {
	if m != nil {
		return m.Height
	}
	return 0
}

func (m *BlockHeader) GetPreviousBlockId() *Hash {
	if m != nil {
		return m.PreviousBlockId
	}
	return nil
}

func (m *BlockHeader) GetSeed() *Hash {
	if m != nil {
		return m.Seed
	}
	return nil
}

func (m *BlockHeader) GetTimestampMs() uint64 {
	if m != nil {
		return m.TimestampMs
	}
	return 0
}

func (m *BlockHeader) GetTransactionsRoot() *Hash {
	if m != nil {
		return m.TransactionsRoot
	}
	return nil
}

func (m *BlockHeader) GetAssetsRoot() *Hash {
	if m != nil {
		return m.AssetsRoot
	}
	return nil
}

func (m *BlockHeader) GetTransactionStatus() *TransactionStatus {
	if m != nil {
		return m.TransactionStatus
	}
	return nil
}

func (m *BlockHeader) GetNonce() uint64 {
	if m != nil {
		return m.Nonce
	}
	return 0
}

func (m *BlockHeader) GetBits() uint64 {
	if m != nil {
		return m.Bits
	}
	return 0
}

type TxHeader struct {
	Version        uint64  `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	SerializedSize uint64  `protobuf:"varint,2,opt,name=serialized_size,json=serializedSize" json:"serialized_size,omitempty"`
	ResultIds      []*Hash `protobuf:"bytes,3,rep,name=result_ids,json=resultIds" json:"result_ids,omitempty"`
	Data           *Hash   `protobuf:"bytes,4,opt,name=data" json:"data,omitempty"`
	ExtHash        *Hash   `protobuf:"bytes,5,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
}

func (m *TxHeader) Reset()                    { *m = TxHeader{} }
func (m *TxHeader) String() string            { return proto.CompactTextString(m) }
func (*TxHeader) ProtoMessage()               {}
func (*TxHeader) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *TxHeader) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *TxHeader) GetSerializedSize() uint64 {
	if m != nil {
		return m.SerializedSize
	}
	return 0
}

func (m *TxHeader) GetResultIds() []*Hash {
	if m != nil {
		return m.ResultIds
	}
	return nil
}

func (m *TxHeader) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *TxHeader) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

type TransactionStatus struct {
	Bitmap []byte `protobuf:"bytes,1,opt,name=bitmap,proto3" json:"bitmap,omitempty"`
}

func (m *TransactionStatus) Reset()                    { *m = TransactionStatus{} }
func (m *TransactionStatus) String() string            { return proto.CompactTextString(m) }
func (*TransactionStatus) ProtoMessage()               {}
func (*TransactionStatus) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *TransactionStatus) GetBitmap() []byte {
	if m != nil {
		return m.Bitmap
	}
	return nil
}

type Mux struct {
	Sources             []*ValueSource      `protobuf:"bytes,1,rep,name=sources" json:"sources,omitempty"`
	Program             *Program            `protobuf:"bytes,2,opt,name=program" json:"program,omitempty"`
	ExtHash             *Hash               `protobuf:"bytes,3,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	WitnessDestinations []*ValueDestination `protobuf:"bytes,4,rep,name=witness_destinations,json=witnessDestinations" json:"witness_destinations,omitempty"`
	WitnessArguments    [][]byte            `protobuf:"bytes,5,rep,name=witness_arguments,json=witnessArguments,proto3" json:"witness_arguments,omitempty"`
}

func (m *Mux) Reset()                    { *m = Mux{} }
func (m *Mux) String() string            { return proto.CompactTextString(m) }
func (*Mux) ProtoMessage()               {}
func (*Mux) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *Mux) GetSources() []*ValueSource {
	if m != nil {
		return m.Sources
	}
	return nil
}

func (m *Mux) GetProgram() *Program {
	if m != nil {
		return m.Program
	}
	return nil
}

func (m *Mux) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Mux) GetWitnessDestinations() []*ValueDestination {
	if m != nil {
		return m.WitnessDestinations
	}
	return nil
}

func (m *Mux) GetWitnessArguments() [][]byte {
	if m != nil {
		return m.WitnessArguments
	}
	return nil
}

type Nonce struct {
	Program           *Program `protobuf:"bytes,1,opt,name=program" json:"program,omitempty"`
	ExtHash           *Hash    `protobuf:"bytes,2,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	WitnessArguments  [][]byte `protobuf:"bytes,3,rep,name=witness_arguments,json=witnessArguments,proto3" json:"witness_arguments,omitempty"`
	WitnessAnchoredId *Hash    `protobuf:"bytes,4,opt,name=witness_anchored_id,json=witnessAnchoredId" json:"witness_anchored_id,omitempty"`
}

func (m *Nonce) Reset()                    { *m = Nonce{} }
func (m *Nonce) String() string            { return proto.CompactTextString(m) }
func (*Nonce) ProtoMessage()               {}
func (*Nonce) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *Nonce) GetProgram() *Program {
	if m != nil {
		return m.Program
	}
	return nil
}

func (m *Nonce) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Nonce) GetWitnessArguments() [][]byte {
	if m != nil {
		return m.WitnessArguments
	}
	return nil
}

func (m *Nonce) GetWitnessAnchoredId() *Hash {
	if m != nil {
		return m.WitnessAnchoredId
	}
	return nil
}

type Coinbase struct {
	WitnessDestination *ValueDestination `protobuf:"bytes,1,opt,name=witness_destination,json=witnessDestination" json:"witness_destination,omitempty"`
	Arbitrary          []byte            `protobuf:"bytes,2,opt,name=arbitrary,proto3" json:"arbitrary,omitempty"`
}

func (m *Coinbase) Reset()                    { *m = Coinbase{} }
func (m *Coinbase) String() string            { return proto.CompactTextString(m) }
func (*Coinbase) ProtoMessage()               {}
func (*Coinbase) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *Coinbase) GetWitnessDestination() *ValueDestination {
	if m != nil {
		return m.WitnessDestination
	}
	return nil
}

func (m *Coinbase) GetArbitrary() []byte {
	if m != nil {
		return m.Arbitrary
	}
	return nil
}

type Output struct {
	Source         *ValueSource `protobuf:"bytes,1,opt,name=source" json:"source,omitempty"`
	ControlProgram *Program     `protobuf:"bytes,2,opt,name=control_program,json=controlProgram" json:"control_program,omitempty"`
	Data           *Hash        `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
	ExtHash        *Hash        `protobuf:"bytes,4,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	Ordinal        uint64       `protobuf:"varint,5,opt,name=ordinal" json:"ordinal,omitempty"`
}

func (m *Output) Reset()                    { *m = Output{} }
func (m *Output) String() string            { return proto.CompactTextString(m) }
func (*Output) ProtoMessage()               {}
func (*Output) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

func (m *Output) GetSource() *ValueSource {
	if m != nil {
		return m.Source
	}
	return nil
}

func (m *Output) GetControlProgram() *Program {
	if m != nil {
		return m.ControlProgram
	}
	return nil
}

func (m *Output) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Output) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Output) GetOrdinal() uint64 {
	if m != nil {
		return m.Ordinal
	}
	return 0
}

type Retirement struct {
	Source  *ValueSource `protobuf:"bytes,1,opt,name=source" json:"source,omitempty"`
	Data    *Hash        `protobuf:"bytes,2,opt,name=data" json:"data,omitempty"`
	ExtHash *Hash        `protobuf:"bytes,3,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	Ordinal uint64       `protobuf:"varint,4,opt,name=ordinal" json:"ordinal,omitempty"`
}

func (m *Retirement) Reset()                    { *m = Retirement{} }
func (m *Retirement) String() string            { return proto.CompactTextString(m) }
func (*Retirement) ProtoMessage()               {}
func (*Retirement) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func (m *Retirement) GetSource() *ValueSource {
	if m != nil {
		return m.Source
	}
	return nil
}

func (m *Retirement) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Retirement) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Retirement) GetOrdinal() uint64 {
	if m != nil {
		return m.Ordinal
	}
	return 0
}

type Issuance struct {
	AnchorId               *Hash             `protobuf:"bytes,1,opt,name=anchor_id,json=anchorId" json:"anchor_id,omitempty"`
	Value                  *AssetAmount      `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	Data                   *Hash             `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
	ExtHash                *Hash             `protobuf:"bytes,4,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	WitnessDestination     *ValueDestination `protobuf:"bytes,5,opt,name=witness_destination,json=witnessDestination" json:"witness_destination,omitempty"`
	WitnessAssetDefinition *AssetDefinition  `protobuf:"bytes,6,opt,name=witness_asset_definition,json=witnessAssetDefinition" json:"witness_asset_definition,omitempty"`
	WitnessArguments       [][]byte          `protobuf:"bytes,7,rep,name=witness_arguments,json=witnessArguments,proto3" json:"witness_arguments,omitempty"`
	WitnessAnchoredId      *Hash             `protobuf:"bytes,8,opt,name=witness_anchored_id,json=witnessAnchoredId" json:"witness_anchored_id,omitempty"`
	Ordinal                uint64            `protobuf:"varint,9,opt,name=ordinal" json:"ordinal,omitempty"`
}

func (m *Issuance) Reset()                    { *m = Issuance{} }
func (m *Issuance) String() string            { return proto.CompactTextString(m) }
func (*Issuance) ProtoMessage()               {}
func (*Issuance) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{15} }

func (m *Issuance) GetAnchorId() *Hash {
	if m != nil {
		return m.AnchorId
	}
	return nil
}

func (m *Issuance) GetValue() *AssetAmount {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Issuance) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Issuance) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Issuance) GetWitnessDestination() *ValueDestination {
	if m != nil {
		return m.WitnessDestination
	}
	return nil
}

func (m *Issuance) GetWitnessAssetDefinition() *AssetDefinition {
	if m != nil {
		return m.WitnessAssetDefinition
	}
	return nil
}

func (m *Issuance) GetWitnessArguments() [][]byte {
	if m != nil {
		return m.WitnessArguments
	}
	return nil
}

func (m *Issuance) GetWitnessAnchoredId() *Hash {
	if m != nil {
		return m.WitnessAnchoredId
	}
	return nil
}

func (m *Issuance) GetOrdinal() uint64 {
	if m != nil {
		return m.Ordinal
	}
	return 0
}

type Spend struct {
	SpentOutputId      *Hash             `protobuf:"bytes,1,opt,name=spent_output_id,json=spentOutputId" json:"spent_output_id,omitempty"`
	Data               *Hash             `protobuf:"bytes,2,opt,name=data" json:"data,omitempty"`
	ExtHash            *Hash             `protobuf:"bytes,3,opt,name=ext_hash,json=extHash" json:"ext_hash,omitempty"`
	WitnessDestination *ValueDestination `protobuf:"bytes,4,opt,name=witness_destination,json=witnessDestination" json:"witness_destination,omitempty"`
	WitnessArguments   [][]byte          `protobuf:"bytes,5,rep,name=witness_arguments,json=witnessArguments,proto3" json:"witness_arguments,omitempty"`
	WitnessAnchoredId  *Hash             `protobuf:"bytes,6,opt,name=witness_anchored_id,json=witnessAnchoredId" json:"witness_anchored_id,omitempty"`
	Ordinal            uint64            `protobuf:"varint,7,opt,name=ordinal" json:"ordinal,omitempty"`
}

func (m *Spend) Reset()                    { *m = Spend{} }
func (m *Spend) String() string            { return proto.CompactTextString(m) }
func (*Spend) ProtoMessage()               {}
func (*Spend) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{16} }

func (m *Spend) GetSpentOutputId() *Hash {
	if m != nil {
		return m.SpentOutputId
	}
	return nil
}

func (m *Spend) GetData() *Hash {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Spend) GetExtHash() *Hash {
	if m != nil {
		return m.ExtHash
	}
	return nil
}

func (m *Spend) GetWitnessDestination() *ValueDestination {
	if m != nil {
		return m.WitnessDestination
	}
	return nil
}

func (m *Spend) GetWitnessArguments() [][]byte {
	if m != nil {
		return m.WitnessArguments
	}
	return nil
}

func (m *Spend) GetWitnessAnchoredId() *Hash {
	if m != nil {
		return m.WitnessAnchoredId
	}
	return nil
}

func (m *Spend) GetOrdinal() uint64 {
	if m != nil {
		return m.Ordinal
	}
	return 0
}

func init() {
	proto.RegisterType((*Hash)(nil), "bc.Hash")
	proto.RegisterType((*Program)(nil), "bc.Program")
	proto.RegisterType((*AssetID)(nil), "bc.AssetID")
	proto.RegisterType((*AssetAmount)(nil), "bc.AssetAmount")
	proto.RegisterType((*AssetDefinition)(nil), "bc.AssetDefinition")
	proto.RegisterType((*ValueSource)(nil), "bc.ValueSource")
	proto.RegisterType((*ValueDestination)(nil), "bc.ValueDestination")
	proto.RegisterType((*BlockHeader)(nil), "bc.BlockHeader")
	proto.RegisterType((*TxHeader)(nil), "bc.TxHeader")
	proto.RegisterType((*TransactionStatus)(nil), "bc.TransactionStatus")
	proto.RegisterType((*Mux)(nil), "bc.Mux")
	proto.RegisterType((*Nonce)(nil), "bc.Nonce")
	proto.RegisterType((*Coinbase)(nil), "bc.Coinbase")
	proto.RegisterType((*Output)(nil), "bc.Output")
	proto.RegisterType((*Retirement)(nil), "bc.Retirement")
	proto.RegisterType((*Issuance)(nil), "bc.Issuance")
	proto.RegisterType((*Spend)(nil), "bc.Spend")
}

func init() { proto.RegisterFile("bc.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 983 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x56, 0xdd, 0x6e, 0xe3, 0x44,
	0x14, 0x96, 0x63, 0x27, 0x76, 0x4e, 0x4a, 0xd3, 0x4e, 0xcb, 0xca, 0x5a, 0x15, 0xa9, 0x18, 0x95,
	0xee, 0x6a, 0xa5, 0xaa, 0x9b, 0x2e, 0x88, 0x0b, 0x6e, 0x0a, 0x05, 0x36, 0x17, 0x05, 0xe4, 0xae,
	0xf6, 0xd6, 0x9a, 0xd8, 0xb3, 0xcd, 0x88, 0xc4, 0x13, 0x66, 0xc6, 0xa1, 0xf4, 0x31, 0xb8, 0xe5,
	0x29, 0xe0, 0x0e, 0xae, 0xf7, 0x89, 0x78, 0x02, 0xe4, 0xe3, 0xb1, 0xe3, 0xfc, 0xed, 0x26, 0xda,
	0xdd, 0x3b, 0x9f, 0x9f, 0x39, 0x7f, 0xdf, 0xf9, 0x3c, 0x03, 0xde, 0x20, 0x3e, 0x9b, 0x48, 0xa1,
	0x05, 0x69, 0x0c, 0xe2, 0xe0, 0x7b, 0x70, 0x9e, 0x53, 0x35, 0x24, 0xbb, 0xd0, 0x98, 0x9e, 0xfb,
	0xd6, 0xb1, 0xf5, 0xa8, 0x15, 0x36, 0xa6, 0xe7, 0x28, 0x3f, 0xf5, 0x1b, 0x46, 0x7e, 0x8a, 0x72,
	0xcf, 0xb7, 0x8d, 0xdc, 0x43, 0xf9, 0xc2, 0x77, 0x8c, 0x7c, 0x11, 0x7c, 0x0d, 0xee, 0xcf, 0x52,
	0xdc, 0x4a, 0x3a, 0x26, 0x9f, 0x00, 0x4c, 0xc7, 0xd1, 0x94, 0x49, 0xc5, 0x45, 0x8a, 0x21, 0x9d,
	0xb0, 0x3d, 0x1d, 0xbf, 0x2c, 0x14, 0x84, 0x80, 0x13, 0x8b, 0x84, 0x61, 0xec, 0x9d, 0x10, 0xbf,
	0x83, 0x3e, 0xb8, 0x97, 0x4a, 0x31, 0xdd, 0xbf, 0x7a, 0xe7, 0x42, 0xae, 0xa1, 0x83, 0xa1, 0x2e,
	0xc7, 0x22, 0x4b, 0x35, 0xf9, 0x1c, 0x3c, 0x9a, 0x8b, 0x11, 0x4f, 0x30, 0x68, 0xa7, 0xd7, 0x39,
	0x1b, 0xc4, 0x67, 0x26, 0x5b, 0xe8, 0xa2, 0xb1, 0x9f, 0x90, 0x07, 0xd0, 0xa2, 0x78, 0x02, 0x53,
	0x39, 0xa1, 0x91, 0x82, 0x3f, 0x2d, 0xe8, 0xa2, 0xf3, 0x15, 0x7b, 0xc5, 0x53, 0xae, 0xf3, 0x0e,
	0x7a, 0xb0, 0x87, 0x9f, 0x74, 0x14, 0x0d, 0x46, 0x22, 0xfe, 0x65, 0x16, 0xdb, 0xcb, 0x63, 0xe7,
	0xf3, 0x0c, 0x77, 0x8d, 0xc7, 0x37, 0xb9, 0x43, 0x3f, 0x21, 0x5f, 0xc2, 0x1e, 0x57, 0x2a, 0xa3,
	0x69, 0xcc, 0xa2, 0x49, 0x31, 0x28, 0xcc, 0x64, 0xea, 0x31, 0xb3, 0x0b, 0xbb, 0xa5, 0x53, 0x39,
	0xcc, 0x23, 0x70, 0x12, 0xaa, 0x29, 0x36, 0x5c, 0x8f, 0x8f, 0xda, 0x60, 0x04, 0x9d, 0x97, 0x74,
	0x94, 0xb1, 0x1b, 0x91, 0xc9, 0x98, 0x91, 0x87, 0x60, 0x4b, 0xf6, 0x6a, 0xa9, 0x96, 0x5c, 0x49,
	0x4e, 0xa0, 0x39, 0xcd, 0x5d, 0x4d, 0xd6, 0x6e, 0x35, 0x85, 0x62, 0x50, 0x61, 0x61, 0x25, 0x0f,
	0xc1, 0x9b, 0x08, 0x85, 0x7d, 0x62, 0x4e, 0x27, 0xac, 0xe4, 0xe0, 0x57, 0xd8, 0xc3, 0x6c, 0x57,
	0x4c, 0x69, 0x9e, 0x52, 0x9c, 0xc5, 0x07, 0x4e, 0xf9, 0x97, 0x0d, 0x1d, 0x1c, 0xe1, 0x73, 0x46,
	0x13, 0x26, 0x89, 0x0f, 0xee, 0xfc, 0x62, 0x95, 0x22, 0x39, 0x85, 0xae, 0x62, 0x92, 0xd3, 0x11,
	0xbf, 0x67, 0x49, 0xa4, 0xf8, 0x3d, 0x33, 0x48, 0xee, 0xce, 0xd4, 0x37, 0xfc, 0x9e, 0xe5, 0x48,
	0x0f, 0x19, 0xbf, 0x1d, 0x6a, 0x93, 0xcc, 0x48, 0xe4, 0x19, 0xec, 0x4f, 0x24, 0x9b, 0x72, 0x91,
	0xa9, 0x19, 0xac, 0xce, 0x42, 0x5f, 0xdd, 0xd2, 0xa5, 0xc4, 0xf5, 0x08, 0x1c, 0xc5, 0x58, 0xe2,
	0x37, 0x17, 0xf1, 0xc9, 0xb5, 0xe4, 0x53, 0xd8, 0xd1, 0x7c, 0xcc, 0x94, 0xa6, 0xe3, 0x49, 0x34,
	0x56, 0x7e, 0x0b, 0x33, 0x76, 0x2a, 0xdd, 0xb5, 0x22, 0x5f, 0xc0, 0xbe, 0x96, 0x34, 0x55, 0x34,
	0xce, 0x1b, 0x56, 0x91, 0x14, 0x42, 0xfb, 0xee, 0x42, 0xb4, 0xbd, 0xba, 0x4b, 0x28, 0x84, 0x26,
	0x8f, 0xa1, 0x83, 0xab, 0x6b, 0x0e, 0x78, 0x0b, 0x07, 0xa0, 0x30, 0xa2, 0xeb, 0x15, 0x90, 0xda,
	0xf1, 0x48, 0x69, 0xaa, 0x33, 0xe5, 0xb7, 0xf1, 0xc4, 0xc7, 0xf9, 0x89, 0x17, 0x33, 0xeb, 0x0d,
	0x1a, 0xc3, 0x7a, 0x49, 0x85, 0x8a, 0x1c, 0x42, 0x33, 0x15, 0x69, 0xcc, 0x7c, 0xc0, 0x1e, 0x0a,
	0x21, 0x27, 0xf3, 0x80, 0x6b, 0xe5, 0x77, 0x50, 0x89, 0xdf, 0xc1, 0x3f, 0x16, 0x78, 0x2f, 0xee,
	0xde, 0x1f, 0x60, 0xa7, 0x00, 0x92, 0xa9, 0x6c, 0x94, 0x73, 0x58, 0xf9, 0xf6, 0xb1, 0x3d, 0xd7,
	0x69, 0xbb, 0xb0, 0xf5, 0x13, 0x55, 0x71, 0xc5, 0x59, 0xc5, 0x15, 0xf2, 0x19, 0x78, 0xec, 0x4e,
	0x47, 0x43, 0xaa, 0x86, 0x4b, 0x68, 0xb9, 0xec, 0x4e, 0xe7, 0x1f, 0xc1, 0x13, 0xd8, 0x5f, 0x9a,
	0x46, 0xbe, 0x31, 0x03, 0xae, 0xc7, 0x74, 0x82, 0x2d, 0xec, 0x84, 0x46, 0x0a, 0xfe, 0xb3, 0xc0,
	0xbe, 0xce, 0xee, 0xc8, 0x63, 0x70, 0x15, 0x12, 0x50, 0xf9, 0x16, 0x56, 0x87, 0x9b, 0x5e, 0x23,
	0x66, 0x58, 0xda, 0xc9, 0x09, 0xb8, 0x6f, 0x60, 0x7f, 0x69, 0x9b, 0xab, 0xd5, 0x5e, 0x53, 0x2b,
	0xf9, 0x01, 0x0e, 0x7f, 0xe3, 0x3a, 0x65, 0x4a, 0x45, 0xc9, 0x8c, 0x91, 0xca, 0x77, 0xb0, 0x86,
	0xc3, 0xaa, 0x86, 0x1a, 0x5d, 0xc3, 0x03, 0x73, 0xa2, 0xa6, 0x53, 0xe4, 0x09, 0xec, 0x97, 0x81,
	0xa8, 0xbc, 0xcd, 0xc6, 0x2c, 0xd5, 0xca, 0x6f, 0x1e, 0xdb, 0x8f, 0x76, 0xc2, 0x3d, 0x63, 0xb8,
	0x2c, 0xf5, 0xc1, 0xbf, 0x16, 0x34, 0x7f, 0x44, 0xec, 0x6b, 0xbd, 0x58, 0x1b, 0xf6, 0xd2, 0x58,
	0xd7, 0xcb, 0xca, 0x12, 0xec, 0xd5, 0x25, 0x90, 0xaf, 0xe0, 0xa0, 0x72, 0x4e, 0xe3, 0xa1, 0x90,
	0x2c, 0x59, 0xc5, 0xd5, 0x32, 0xe2, 0xa5, 0xf1, 0xe9, 0x27, 0x81, 0x00, 0xef, 0x5b, 0xc1, 0xd3,
	0x01, 0x55, 0x8c, 0x7c, 0x37, 0x8b, 0x52, 0x1b, 0x9f, 0x69, 0x65, 0xf5, 0xf4, 0xc8, 0xf2, 0xf4,
	0xc8, 0x11, 0xb4, 0xa9, 0x1c, 0x70, 0x2d, 0xa9, 0xfc, 0xdd, 0xdc, 0x69, 0x33, 0x45, 0xf0, 0xda,
	0x82, 0xd6, 0x4f, 0x99, 0x9e, 0x64, 0x9a, 0x9c, 0x42, 0xab, 0xd8, 0x02, 0x93, 0x62, 0x69, 0x49,
	0x8c, 0x99, 0x3c, 0x83, 0x6e, 0x2c, 0x52, 0x2d, 0xc5, 0xe8, 0x4d, 0x37, 0xc5, 0xae, 0xf1, 0xd9,
	0xe8, 0xa2, 0x98, 0x03, 0xc1, 0x59, 0x07, 0x82, 0x0f, 0xae, 0x90, 0x09, 0x4f, 0xe9, 0x08, 0x09,
	0xe2, 0x84, 0xa5, 0x18, 0xfc, 0x61, 0x01, 0x84, 0x4c, 0x73, 0xc9, 0x72, 0x04, 0x36, 0x6f, 0xa5,
	0x2c, 0xaa, 0xf1, 0xd6, 0xa2, 0xec, 0x0d, 0x8a, 0x72, 0xe6, 0x8b, 0xfa, 0xdb, 0x06, 0xaf, 0x6f,
	0xae, 0x4b, 0x72, 0x02, 0xed, 0x62, 0x17, 0x56, 0x5d, 0xc6, 0x5e, 0x61, 0xea, 0x27, 0x9b, 0x5e,
	0x49, 0xef, 0x61, 0x98, 0x6b, 0xd6, 0xab, 0xb9, 0xe5, 0x7a, 0x5d, 0x83, 0x5f, 0xed, 0x3a, 0xbe,
	0x63, 0x92, 0xea, 0x1d, 0x82, 0xb7, 0x49, 0xa7, 0x77, 0x50, 0xf5, 0x30, 0x7b, 0xa2, 0x84, 0x0f,
	0xca, 0xdd, 0x5f, 0x78, 0xba, 0xac, 0xe4, 0x99, 0xbb, 0x1d, 0xcf, 0xbc, 0xb7, 0xf2, 0xac, 0x0e,
	0x5a, 0x7b, 0x1e, 0xb4, 0xd7, 0x0d, 0x68, 0xde, 0x4c, 0x58, 0x9a, 0x90, 0x73, 0xe8, 0xaa, 0x09,
	0x4b, 0x75, 0x24, 0x90, 0x1f, 0xab, 0x70, 0xfb, 0x08, 0x1d, 0x0a, 0xfe, 0x14, 0x77, 0xed, 0xbb,
	0x6e, 0xd3, 0x1a, 0x54, 0x9c, 0x2d, 0x51, 0xd9, 0xe6, 0x8f, 0xb9, 0x6e, 0x8c, 0xad, 0xad, 0xc6,
	0xe8, 0xce, 0x8d, 0x71, 0xd0, 0xc2, 0x17, 0xfc, 0xc5, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0x14,
	0x83, 0x0d, 0x5b, 0xcd, 0x0b, 0x00, 0x00,
}
