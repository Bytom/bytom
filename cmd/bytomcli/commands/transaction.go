package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"

	"github.com/bytom/api"
	"github.com/bytom/blockchain/txbuilder"
	chainjson "github.com/bytom/encoding/json"
	"github.com/bytom/protocol/bc/types"
	"github.com/bytom/util"
)

func init() {
	buildTransactionCmd.PersistentFlags().StringVarP(&buildType, "type", "t", "", "transaction type, valid types: 'issue', 'spend', 'address', 'retire', 'program', 'unlock'")
	buildTransactionCmd.PersistentFlags().StringVarP(&receiverProgram, "receiver", "r", "", "program of receiver when type is spend")
	buildTransactionCmd.PersistentFlags().StringVarP(&address, "address", "a", "", "address of receiver when type is address")
	buildTransactionCmd.PersistentFlags().StringVarP(&program, "program", "p", "", "program of receiver when type is program")
	buildTransactionCmd.PersistentFlags().StringVarP(&arbitrary, "arbitrary", "v", "", "additional arbitrary data when type is retire")
	buildTransactionCmd.PersistentFlags().StringVarP(&btmGas, "gas", "g", "20000000", "gas of this transaction")
	buildTransactionCmd.PersistentFlags().StringVarP(&contractName, "contract-name", "c", "",
		"name of template contract, currently supported: 'LockWithPublicKey', 'LockWithMultiSig', 'LockWithPublicKeyHash',"+
			"\n\t\t\t       'RevealPreimage', 'TradeOffer', 'Escrow', 'CallOption', 'LoanCollateral'")
	buildTransactionCmd.PersistentFlags().BoolVar(&pretty, "pretty", false, "pretty print json result")
	buildTransactionCmd.PersistentFlags().BoolVar(&alias, "alias", false, "use alias build transaction")

	signTransactionCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "password of the account which sign these transaction(s)")
	signTransactionCmd.PersistentFlags().BoolVar(&pretty, "pretty", false, "pretty print json result")

	listTransactionsCmd.PersistentFlags().StringVar(&txID, "id", "", "transaction id")
	listTransactionsCmd.PersistentFlags().StringVar(&account, "account_id", "", "account id")
	listTransactionsCmd.PersistentFlags().BoolVar(&detail, "detail", false, "list transactions details")
	listTransactionsCmd.PersistentFlags().BoolVar(&unconfirmed, "unconfirmed", false, "list unconfirmed transactions")
}

var (
	buildType       = ""
	btmGas          = ""
	receiverProgram = ""
	address         = ""
	password        = ""
	pretty          = false
	alias           = false
	txID            = ""
	account         = ""
	detail          = false
	unconfirmed     = false
	arbitrary       = ""
	program         = ""
	contractName    = ""
)

var buildIssueReqFmt = `
	{"actions": [
		{"type": "spend_account", "asset_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount":%s, "account_id": "%s"},
		{"type": "issue", "asset_id": "%s", "amount": %s},
		{"type": "control_address", "asset_id": "%s", "amount": %s, "address": "%s"}
	]}`

var buildIssueReqFmtByAlias = `
	{"actions": [
		{"type": "spend_account", "asset_alias": "BTM", "amount":%s, "account_alias": "%s"},
		{"type": "issue", "asset_alias": "%s", "amount": %s},
		{"type": "control_address", "asset_alias": "%s", "amount": %s, "address": "%s"}
	]}`

var buildSpendReqFmt = `
	{"actions": [
		{"type": "spend_account", "asset_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount":%s, "account_id": "%s"},
		{"type": "spend_account", "asset_id": "%s","amount": %s,"account_id": "%s"},
		{"type": "control_receiver", "asset_id": "%s", "amount": %s, "receiver":{"control_program": "%s"}}
	]}`

var buildSpendReqFmtByAlias = `
	{"actions": [
		{"type": "spend_account", "asset_alias": "BTM", "amount":%s, "account_alias": "%s"},
		{"type": "spend_account", "asset_alias": "%s","amount": %s,"account_alias": "%s"},
		{"type": "control_receiver", "asset_alias": "%s", "amount": %s, "receiver":{"control_program": "%s"}}
	]}`

var buildRetireReqFmt = `
	{"actions": [
		{"type": "spend_account", "asset_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount":%s, "account_id": "%s"},
		{"type": "spend_account", "asset_id": "%s", "amount": %s, "account_id": "%s"},
		{"type": "retire", "asset_id": "%s", "amount": %s, "arbitrary": "%s"}
	]}`

var buildRetireReqFmtByAlias = `
	{"actions": [
		{"type": "spend_account", "asset_alias": "BTM", "amount":%s, "account_alias": "%s"},
		{"type": "spend_account", "asset_alias": "%s", "amount": %s, "account_alias": "%s"},
		{"type": "retire", "asset_alias": "%s", "amount": %s, "arbitrary": "%s"}
	]}`

var buildControlAddressReqFmt = `
	{"actions": [
		{"type": "spend_account", "asset_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount":%s, "account_id": "%s"},
		{"type": "spend_account", "asset_id": "%s","amount": %s,"account_id": "%s"},
		{"type": "control_address", "asset_id": "%s", "amount": %s,"address": "%s"}
	]}`

var buildControlAddressReqFmtByAlias = `
	{"actions": [
		{"type": "spend_account", "asset_alias": "BTM", "amount":%s, "account_alias": "%s"},
		{"type": "spend_account", "asset_alias": "%s","amount": %s, "account_alias": "%s"},
		{"type": "control_address", "asset_alias": "%s", "amount": %s,"address": "%s"}
	]}`

var buildControlProgramReqFmt = `
	{"actions": [
		{"type": "spend_account", "asset_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "amount":%s, "account_id": "%s"},
		{"type": "spend_account", "asset_id": "%s","amount": %s,"account_id": "%s"},
		{"type": "control_program", "asset_id": "%s", "amount": %s, "control_program": "%s"}
	]}`

var buildControlProgramReqFmtByAlias = `
	{"actions": [
		{"type": "spend_account", "asset_alias": "btm", "amount":%s, "account_alias": "%s"},
		{"type": "spend_account", "asset_alias": "%s","amount": %s,"account_alias": "%s"},
		{"type": "control_program", "asset_alias": "%s", "amount": %s, "control_program": "%s"}
	]}`

var buildTransactionCmd = &cobra.Command{
	Use:   "build-transaction <accountID|alias> <assetID|alias> <amount> [outputID]",
	Short: "Build one transaction template,default use account id and asset id",
	Args:  cobra.RangeArgs(3, 20),
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("type")
		if buildType == "spend" {
			cmd.MarkFlagRequired("receiver")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		var buildReqStr string
		accountInfo := args[0]
		assetInfo := args[1]
		amount := args[2]
		switch buildType {
		case "issue":
			if alias {
				buildReqStr = fmt.Sprintf(buildIssueReqFmtByAlias, btmGas, accountInfo, assetInfo, amount, assetInfo, amount, address)
				break
			}
			buildReqStr = fmt.Sprintf(buildIssueReqFmt, btmGas, accountInfo, assetInfo, amount, assetInfo, amount, address)
		case "spend":
			if alias {
				buildReqStr = fmt.Sprintf(buildSpendReqFmtByAlias, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, receiverProgram)
				break
			}
			buildReqStr = fmt.Sprintf(buildSpendReqFmt, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, receiverProgram)
		case "retire":
			if alias {
				buildReqStr = fmt.Sprintf(buildRetireReqFmtByAlias, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, arbitrary)
				break
			}
			buildReqStr = fmt.Sprintf(buildRetireReqFmt, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, arbitrary)
		case "address":
			if alias {
				buildReqStr = fmt.Sprintf(buildControlAddressReqFmtByAlias, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, address)
				break
			}
			buildReqStr = fmt.Sprintf(buildControlAddressReqFmt, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, address)
		case "program":
			if alias {
				buildReqStr = fmt.Sprintf(buildControlProgramReqFmtByAlias, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, program)
				break
			}
			buildReqStr = fmt.Sprintf(buildControlProgramReqFmt, btmGas, accountInfo, assetInfo, amount, accountInfo, assetInfo, amount, program)
		case "unlock":
			usage := "Usage:\n  bytomcli build-transaction <accountID|alias> <assetID|alias> <amount> <outputID> -c <contractName>"
			if len(args) <= 3 {
				jww.ERROR.Printf("%s <contract_argument> ... [flags]\n\n", usage)
				os.Exit(util.ErrLocalExe)
			}
			outputID := args[3]
			switch contractName {
			case "LockWithPublicKey":
				if len(args) != 7 {
					jww.ERROR.Printf("%s <rootPub> <path1> <path2> [flags]\n\n", usage)
					os.Exit(util.ErrLocalExe)
				}

				rootPub := args[4]
				path1 := args[5]
				path2 := args[6]
				if alias {
					buildReqStr = fmt.Sprintf(buildLockWithPublicKeyReqFmtByAlias, outputID, rootPub, path1, path2, assetInfo, amount, program, btmGas, accountInfo)
					break
				}
				buildReqStr = fmt.Sprintf(buildLockWithPublicKeyReqFmt, outputID, rootPub, path1, path2, assetInfo, amount, program, btmGas, accountInfo)

			case "LockWithMultiSig":
				if len(args) != 10 {
					jww.ERROR.Printf("%s <rootPub1> <path11> <path12> <rootPub2> <path21> <path22> [flags]\n\n", usage)
					os.Exit(util.ErrLocalExe)
				}

				rootPub1 := args[4]
				path11 := args[5]
				path12 := args[6]
				rootPub2 := args[7]
				path21 := args[8]
				path22 := args[9]
				if alias {
					buildReqStr = fmt.Sprintf(buildLockWithMultiSigReqFmtByAlias, outputID, rootPub1, path11, path12, rootPub2, path21, path22, assetInfo, amount, program, btmGas, accountInfo)
					break
				}
				buildReqStr = fmt.Sprintf(buildLockWithMultiSigReqFmt, outputID, rootPub1, path11, path12, rootPub2, path21, path22, assetInfo, amount, program, btmGas, accountInfo)

			case "LockWithPublicKeyHash":
				if len(args) != 8 {
					jww.ERROR.Printf("%s <pubkey> <rootPub> <path1> <path2> [flags]\n\n", usage)
					os.Exit(util.ErrLocalExe)
				}

				pubkey := args[4]
				rootPub := args[5]
				path1 := args[6]
				path2 := args[7]
				if alias {
					buildReqStr = fmt.Sprintf(buildLockWithPublicKeyHashReqFmtByAlias, outputID, pubkey, rootPub, path1, path2, assetInfo, amount, program, btmGas, accountInfo)
					break
				}
				buildReqStr = fmt.Sprintf(buildLockWithPublicKeyHashReqFmt, outputID, pubkey, rootPub, path1, path2, assetInfo, amount, program, btmGas, accountInfo)

			case "RevealPreimage":
				if len(args) != 5 {
					jww.ERROR.Printf("%s <value> [flags]\n\n", usage)
					os.Exit(util.ErrLocalExe)
				}

				value := args[4]
				if alias {
					buildReqStr = fmt.Sprintf(buildRevealPreimageReqFmtByAlias, outputID, value, assetInfo, amount, program, btmGas, accountInfo)
					break
				}
				buildReqStr = fmt.Sprintf(buildRevealPreimageReqFmt, outputID, value, assetInfo, amount, program, btmGas, accountInfo)

			case "TradeOffer":
				clauseTrade := "00000000"
				clauseCancel := "13000000"
				tradeOfferEnding := "1a000000"

				switch {
				case len(args) <= 4:
					jww.ERROR.Printf("%s <clauseSelector> (<innerAccountID|alias> <innerAssetID|alias> <innerAmount> <innerProgram>) | (<rootPub> <path1> <path2>) [flags]\n\n", usage)
					os.Exit(util.ErrLocalExe)
				case args[4] == clauseTrade:
					if len(args) != 9 {
						jww.ERROR.Printf("%s <clauseSelector> <innerAccountID|alias> <innerAssetID|alias> <innerAmount> <innerProgram> [flags]\n\n", usage)
						os.Exit(util.ErrLocalExe)
					}

					innerAccountInfo := args[5]
					innerAssetInfo := args[6]
					innerAmount := args[7]
					innerProgram := args[8]
					if alias {
						buildReqStr = fmt.Sprintf(buildTradeOfferClauseTradeReqFmtByAlias, outputID, clauseTrade,
							innerAssetInfo, innerAmount, innerProgram,
							innerAssetInfo, innerAmount, innerAccountInfo,
							btmGas, accountInfo,
							assetInfo, amount, program)
					} else {
						buildReqStr = fmt.Sprintf(buildTradeOfferClauseTradeReqFmt, outputID, clauseTrade,
							innerAssetInfo, innerAmount, innerProgram,
							innerAssetInfo, innerAmount, innerAccountInfo,
							btmGas, accountInfo,
							assetInfo, amount, program)
					}
				case args[4] == clauseCancel:
					if len(args) != 8 {
						jww.ERROR.Printf("%s <clauseSelector> <rootPub> <path1> <path2> [flags]\n\n", usage)
						os.Exit(util.ErrLocalExe)
					}

					rootPub := args[5]
					path1 := args[6]
					path2 := args[7]
					if alias {
						buildReqStr = fmt.Sprintf(buildTradeOfferClauseCancelReqFmtByAlias, outputID, rootPub, path1, path2, clauseCancel, assetInfo, amount, program, btmGas, accountInfo)
					} else {
						buildReqStr = fmt.Sprintf(buildTradeOfferClauseCancelReqFmt, outputID, rootPub, path1, path2, clauseCancel, assetInfo, amount, program, btmGas, accountInfo)
					}
				case args[4] == tradeOfferEnding:
					jww.ERROR.Printf("Clause ending was selected in contract %s, ending exit!\n\n", contractName)
					os.Exit(util.ErrLocalExe)
				default:
					jww.ERROR.Printf("selected clause [%s] error, contract %s's clause must in set:[%s, %s, %s]\n\n",
						args[4], contractName, clauseTrade, clauseCancel, tradeOfferEnding)
					os.Exit(util.ErrLocalExe)
				}

			default:
				jww.ERROR.Printf("Invalid Contract template: %s\n\n", contractName)
				os.Exit(util.ErrLocalExe)
			}

		default:
			jww.ERROR.Println("Invalid transaction template type")
			os.Exit(util.ErrLocalExe)
		}

		var buildReq api.BuildRequest
		if err := json.Unmarshal([]byte(buildReqStr), &buildReq); err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		data, exitCode := util.ClientCall("/build-transaction", &buildReq)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		if pretty {
			printJSON(data)
			return
		}

		dataMap, ok := data.(map[string]interface{})
		if ok != true {
			jww.ERROR.Println("invalid type assertion")
			os.Exit(util.ErrLocalParse)
		}

		rawTemplate, err := json.Marshal(dataMap)
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalParse)
		}

		jww.FEEDBACK.Printf("Template Type: %s\n%s\n", buildType, string(rawTemplate))
	},
}

var signTransactionCmd = &cobra.Command{
	Use:   "sign-transaction  <json templates>",
	Short: "Sign transaction templates with account password",
	Args:  cobra.ExactArgs(1),
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.MarkFlagRequired("password")
	},
	Run: func(cmd *cobra.Command, args []string) {
		template := txbuilder.Template{}

		err := json.Unmarshal([]byte(args[0]), &template)
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		var req = struct {
			Password string             `json:"password"`
			Txs      txbuilder.Template `json:"transaction"`
		}{Password: password, Txs: template}

		jww.FEEDBACK.Printf("\n\n")
		data, exitCode := util.ClientCall("/sign-transaction", &req)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		if pretty {
			printJSON(data)
			return
		}

		dataMap, ok := data.(map[string]interface{})
		if ok != true {
			jww.ERROR.Println("invalid type assertion")
			os.Exit(util.ErrLocalParse)
		}

		rawSign, err := json.Marshal(dataMap)
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalParse)
		}
		jww.FEEDBACK.Printf("\nSign Template:\n%s\n", string(rawSign))
	},
}

var submitTransactionCmd = &cobra.Command{
	Use:   "submit-transaction  <signed json raw_transaction>",
	Short: "Submit signed transaction",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var ins = struct {
			Tx types.Tx `json:"raw_transaction"`
		}{}

		err := json.Unmarshal([]byte(args[0]), &ins)
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		data, exitCode := util.ClientCall("/submit-transaction", &ins)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var estimateTransactionGasCmd = &cobra.Command{
	Use:   "estimate-transaction-gas  <json templates>",
	Short: "estimate gas for build transaction",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		template := txbuilder.Template{}

		err := json.Unmarshal([]byte(args[0]), &template)
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		var req = struct {
			TxTemplate txbuilder.Template `json:"transaction_template"`
		}{TxTemplate: template}

		data, exitCode := util.ClientCall("/estimate-transaction-gas", &req)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var decodeRawTransactionCmd = &cobra.Command{
	Use:   "decode-raw-transaction <raw_transaction>",
	Short: "decode the raw transaction",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var ins = struct {
			Tx types.Tx `json:"raw_transaction"`
		}{}

		err := ins.Tx.UnmarshalText([]byte(args[0]))
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		data, exitCode := util.ClientCall("/decode-raw-transaction", &ins)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var getTransactionCmd = &cobra.Command{
	Use:   "get-transaction <hash>",
	Short: "get the transaction by matching the given transaction hash",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		txInfo := &struct {
			TxID string `json:"tx_id"`
		}{TxID: args[0]}

		data, exitCode := util.ClientCall("/get-transaction", txInfo)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var listTransactionsCmd = &cobra.Command{
	Use:   "list-transactions",
	Short: "List the transactions",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		filter := struct {
			ID          string `json:"id"`
			AccountID   string `json:"account_id"`
			Detail      bool   `json:"detail"`
			Unconfirmed bool   `json:"unconfirmed"`
		}{ID: txID, AccountID: account, Detail: detail, Unconfirmed: unconfirmed}

		data, exitCode := util.ClientCall("/list-transactions", &filter)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSONList(data)
	},
}

var getUnconfirmedTransactionCmd = &cobra.Command{
	Use:   "get-unconfirmed-transaction <hash>",
	Short: "get unconfirmed transaction by matching the given transaction hash",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		txID, err := hex.DecodeString(args[0])
		if err != nil {
			jww.ERROR.Println(err)
			os.Exit(util.ErrLocalExe)
		}

		txInfo := &struct {
			TxID chainjson.HexBytes `json:"tx_id"`
		}{TxID: txID}

		data, exitCode := util.ClientCall("/get-unconfirmed-transaction", txInfo)
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var listUnconfirmedTransactionsCmd = &cobra.Command{
	Use:   "list-unconfirmed-transactions",
	Short: "list unconfirmed transactions hashes",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		data, exitCode := util.ClientCall("/list-unconfirmed-transactions")
		if exitCode != util.Success {
			os.Exit(exitCode)
		}

		printJSON(data)
	},
}

var gasRateCmd = &cobra.Command{
	Use:   "gas-rate",
	Short: "Print the current gas rate",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		data, exitCode := util.ClientCall("/gas-rate")
		if exitCode != util.Success {
			os.Exit(exitCode)
		}
		printJSON(data)
	},
}
