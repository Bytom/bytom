package legacy

type IssuanceWitness struct {
	AssetDefinition []byte
	VMVersion       uint64
	IssuanceProgram []byte
	Arguments       [][]byte
}
