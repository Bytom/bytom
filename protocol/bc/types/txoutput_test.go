package types

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"

	"github.com/bytom/bytom/encoding/blockchain"
	"github.com/bytom/bytom/protocol/bc"
	"github.com/bytom/bytom/testutil"
)

func TestSerializationOriginalTxOutput(t *testing.T) {
	assetID := testutil.MustDecodeAsset("81756fdab39a17163b0ce582ee4ee256fb4d1e156c692b997d608a42ecb38d47")
	txOutput := NewOriginalTxOutput(assetID, 254354, []byte("TestSerializationTxOutput"))

	wantHex := strings.Join([]string{
		"01", // asset version
		"00", // output type
		"3e", // serialization length
		"81756fdab39a17163b0ce582ee4ee256fb4d1e156c692b997d608a42ecb38d47", // assetID
		"92c30f", // amount
		"01",     // version
		"19",     // control program length
		"5465737453657269616c697a6174696f6e54784f7574707574", // control program
		"00", // witness length
	}, "")

	// Test convert struct to hex
	var buffer bytes.Buffer
	if err := txOutput.writeTo(&buffer); err != nil {
		t.Fatal(err)
	}

	gotHex := hex.EncodeToString(buffer.Bytes())
	if gotHex != wantHex {
		t.Errorf("serialization bytes = %s want %s", gotHex, wantHex)
	}

	// Test convert hex to struct
	var gotTxOutput TxOutput
	decodeHex, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	if err := gotTxOutput.readFrom(blockchain.NewReader(decodeHex)); err != nil {
		t.Fatal(err)
	}

	if !testutil.DeepEqual(*txOutput, gotTxOutput) {
		t.Errorf("expected marshaled/unmarshaled txoutput to be:\n%sgot:\n%s", spew.Sdump(*txOutput), spew.Sdump(gotTxOutput))
	}
}

func TestSerializationVoteOutput(t *testing.T) {
	assetID := testutil.MustDecodeAsset("81756fdab39a17163b0ce582ee4ee256fb4d1e156c692b997d608a42ecb38d47")
	voteTxOutput := NewVoteOutput(assetID, 1000, []byte("TestSerializationTxOutput"), []byte("af594006a40837d9f028daabb6d589df0b9138daefad5683e5233c2646279217294a8d532e60863bcf196625a35fb8ceeffa3c09610eb92dcfb655a947f13269"))

	wantHex := strings.Join([]string{
		"01",   // asset version
		"01",   // outType
		"bf01", // serialization length
		"8001", // output xpub length
		"6166353934303036613430383337643966303238646161626236643538396466306239313338646165666164353638336535323333633236343632373932313732393461386435333265363038363362636631393636323561333566623863656566666133633039363130656239326463666236353561393437663133323639", // xpub
		"81756fdab39a17163b0ce582ee4ee256fb4d1e156c692b997d608a42ecb38d47", // assetID
		"e807", // amount
		"01",   // version
		"19",   // control program length
		"5465737453657269616c697a6174696f6e54784f7574707574", // control program
		"00", // witness length
	}, "")

	// Test convert struct to hex
	var buffer bytes.Buffer
	if err := voteTxOutput.writeTo(&buffer); err != nil {
		t.Fatal(err)
	}

	gotHex := hex.EncodeToString(buffer.Bytes())
	if gotHex != wantHex {
		t.Errorf("serialization bytes = %s want %s", gotHex, wantHex)
	}

	// Test convert hex to struct
	var gotTxOutput TxOutput
	decodeHex, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	if err := gotTxOutput.readFrom(blockchain.NewReader(decodeHex)); err != nil {
		t.Fatal(err)
	}

	if !testutil.DeepEqual(*voteTxOutput, gotTxOutput) {
		t.Errorf("expected marshaled/unmarshaled txoutput to be:\n%sgot:\n%s", spew.Sdump(*voteTxOutput), spew.Sdump(gotTxOutput))
	}
}

func TestComputeOutputID(t *testing.T) {
	btmAssetID := testutil.MustDecodeAsset("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	cases := []struct {
		sc           *SpendCommitment
		wantOutputID string
	}{
		{
			sc: &SpendCommitment{
				AssetAmount:    bc.AssetAmount{AssetId: &btmAssetID, Amount: 1000},
				SourceID:       testutil.MustDecodeHash("4b5cb973f5bef4eadde4c89b92ee73312b940e84164da0594149554cc8a2adea"),
				SourcePosition: 2,
				VMVersion:      1,
				ControlProgram: testutil.MustDecodeHexString("0014cb9f2391bafe2bc1159b2c4c8a0f17ba1b4dd94e"),
			},
			wantOutputID: "c9902bad769008917d14710d60391a43fe6cbd255c839045425c65f749c39d81",
		},
		{
			sc: &SpendCommitment{
				AssetAmount:    bc.AssetAmount{AssetId: &btmAssetID, Amount: 999},
				SourceID:       testutil.MustDecodeHash("9e74e35362ffc73c8967aa0008da8fcbc62a21d35673fb970445b5c2972f8603"),
				SourcePosition: 2,
				VMVersion:      1,
				ControlProgram: testutil.MustDecodeHexString("001418549d84daf53344d32563830c7cf979dc19d5c0"),
			},
			wantOutputID: "4d038eed93338f4dfc8603101bc70f4b8e662e69828c6dadf4207b5dfaf66275",
		},
	}

	for _, c := range cases {
		outputID, err := ComputeOutputID(c.sc)
		if err != nil {
			t.Fatal(err)
		}

		if c.wantOutputID != outputID.String() {
			t.Errorf("test compute output id fail, got:%s, want:%s", outputID.String(), c.wantOutputID)
		}
	}
}
