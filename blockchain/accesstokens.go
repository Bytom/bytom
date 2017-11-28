package blockchain

import (
	"context"
	"encoding/hex"

	"github.com/bytom/errors"
)

var errCurrentToken = errors.New("token cannot delete itself")

func (a *BlockchainReactor) createAccessToken(ctx context.Context, x struct{ ID, Type string }) interface{} {
	token, err := a.accessTokens.Create(ctx, x.ID, x.Type)
	if err != nil {
		return jsendWrapper(nil, ERROR, err.Error())
	}

	return jsendWrapper(token, SUCCESS, "")
}

func (a *BlockchainReactor) listAccessTokens(ctx context.Context) interface{} {
	tokens, err := a.accessTokens.List(ctx)
	if err != nil {
		return jsendWrapper(nil, ERROR, err.Error())
	}

	return jsendWrapper(tokens, SUCCESS, "")
}

func (a *BlockchainReactor) deleteAccessToken(ctx context.Context, x struct{ ID, Token string }) interface{} {
	//TODO Add delete permission verify.
	if err := a.accessTokens.Delete(ctx, x.ID); err != nil {
		return jsendWrapper(nil, ERROR, err.Error())
	}
	return jsendWrapper("success", SUCCESS, "")
}

func (a *BlockchainReactor) checkAccessToken(ctx context.Context, x struct{ ID, Secret string }) interface{} {
	secret, err := hex.DecodeString(x.Secret)
	if err != nil {
		return jsendWrapper(nil, ERROR, err.Error())
	}
	result, err := a.accessTokens.Check(ctx, x.ID, secret)
	if err != nil {
		return jsendWrapper(nil, ERROR, err.Error())
	}
	if result == true {
		return jsendWrapper("success", SUCCESS, "")
	}
	return jsendWrapper("fail", SUCCESS, "")
}
