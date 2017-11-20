package blockchain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bytom/errors"
)

var errCurrentToken = errors.New("token cannot delete itself")

func (a *BlockchainReactor) createAccessToken(ctx context.Context, x struct{ ID, Type string }) interface{} {
	token, err := a.accessTokens.Create(ctx, x.ID, x.Type)
	if err != nil {
		return err.Error()
	}

	return token
}

func (a *BlockchainReactor) listAccessTokens(ctx context.Context) interface{} {
	tokens, err := a.accessTokens.List(ctx)
	if err != nil {
		return err.Error()
	}

	var result string
	for i, v := range tokens {
		value, _ := json.Marshal(v)
		result += fmt.Sprintf("%d %v\n", i, string(value))
	}
	return result
}

func (a *BlockchainReactor) deleteAccessToken(ctx context.Context, x struct{ ID, Token string }) interface{} {
	//TODO Add delete permission verify.
	if err := a.accessTokens.Delete(ctx, x.ID); err != nil {
		return err.Error()
	}
	return "success!"
}

func (a *BlockchainReactor) checkAccessToken(ctx context.Context, x struct{ ID, Secret string }) interface{} {
	secret, err := hex.DecodeString(x.Secret)
	if err != nil {
		return err.Error()
	}
	result, err := a.accessTokens.Check(ctx, x.ID, secret)
	if err != nil {
		return err.Error()
	}
	return result
}
