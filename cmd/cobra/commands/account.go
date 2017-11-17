package commands

import (
	"context"

	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"

	"github.com/bytom/blockchain/query"
	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/encoding/json"
)

var createAccountCmd = &cobra.Command{
	Use:   "create-account",
	Short: "Create an account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			jww.ERROR.Println("create-account takes no args")
		}

		xprv, err := chainkd.NewXPrv(nil)
		if err != nil {
			jww.ERROR.Println("NewXprv error")
		}

		xpub := xprv.XPub()
		jww.FEEDBACK.Printf("xprv: %v\n", xprv)
		jww.FEEDBACK.Printf("xpub: %v\n", xpub)

		type Ins struct {
			RootXPubs   []chainkd.XPub `json:"root_xpubs"`
			Quorum      int
			Alias       string
			Tags        map[string]interface{}
			ClientToken string `json:"client_token"`
		}

		var ins Ins
		ins.RootXPubs = []chainkd.XPub{xpub}
		ins.Quorum = 1
		ins.Alias = "alice"
		ins.Tags = map[string]interface{}{"test_tag": "v0"}
		ins.ClientToken = args[0]

		account := make([]query.AnnotatedAccount, 1)

		client := mustRPCClient()
		client.Call(context.Background(), "/create-account", &[]Ins{ins}, &account)

		jww.FEEDBACK.Printf("responses: %v\n", account[0])
	},
}

var bindAccountCmd = &cobra.Command{
	Use:   "bind-account",
	Short: "Bind an account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			jww.ERROR.Println("bind-account need args [account alias name] [account pub key]")
		}

		var xpub chainkd.XPub
		err := xpub.UnmarshalText([]byte(args[1]))
		if err != nil {
			jww.FEEDBACK.Printf("xpub unmarshal error: %v\n", xpub)
		}
		jww.FEEDBACK.Printf("xpub: %v\n", xpub)

		type Ins struct {
			RootXPubs   []chainkd.XPub `json:"root_xpubs"`
			Quorum      int
			Alias       string
			Tags        map[string]interface{}
			ClientToken string `json:"client_token"`
		}

		var ins Ins
		ins.RootXPubs = []chainkd.XPub{xpub}
		ins.Quorum = 1
		ins.Alias = args[0]
		ins.Tags = map[string]interface{}{"test_tag": "v0"}
		ins.ClientToken = args[0]

		account := make([]query.AnnotatedAccount, 1)

		client := mustRPCClient()
		client.Call(context.Background(), "/bind-account", &[]Ins{ins}, &account)

		jww.FEEDBACK.Printf("responses: %v\n", account[0])
		jww.FEEDBACK.Printf("account id: %v\n", account[0].ID)
	},
}

var listAccountsCmd = &cobra.Command{
	Use:   "list-accounts",
	Short: "List the existing accounts",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			jww.ERROR.Print("list-accounts takes no args")
		}

		type requestQuery struct {
			Filter       string        `json:"filter,omitempty"`
			FilterParams []interface{} `json:"filter_params,omitempty"`
			SumBy        []string      `json:"sum_by,omitempty"`
			PageSize     int           `json:"page_size"`
			AscLongPoll  bool          `json:"ascending_with_long_poll,omitempty"`
			Timeout      json.Duration `json:"timeout"`
			After        string        `json:"after"`
			StartTimeMS  uint64        `json:"start_time,omitempty"`
			EndTimeMS    uint64        `json:"end_time,omitempty"`
			TimestampMS  uint64        `json:"timestamp,omitempty"`
			Type         string        `json:"type"`
			Aliases      []string      `json:"aliases,omitempty"`
		}

		var in requestQuery

		responses := make([]interface{}, 0)

		client := mustRPCClient()
		client.Call(context.Background(), "/list-accounts", in, &responses)

		if len(responses) > 0 {
			for idx, item := range responses {
				jww.FEEDBACK.Println(idx, ": ", item)
			}
		} else {
			jww.FEEDBACK.Printf("No accounts")
		}
	},
}
