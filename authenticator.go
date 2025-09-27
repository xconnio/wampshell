package wampshell

import (
	"fmt"

	"github.com/xconnio/wampproto-go/auth"
)

type ServerAuthenticator struct {
	keyStore *KeyStore
}

func NewAuthenticator(keyStore *KeyStore) *ServerAuthenticator {
	return &ServerAuthenticator{keyStore: keyStore}
}

func (a *ServerAuthenticator) Methods() []auth.Method {
	return []auth.Method{auth.MethodCryptoSign}
}

func (a *ServerAuthenticator) Authenticate(request auth.Request) (auth.Response, error) {
	cryptosignRequest, ok := request.(*auth.RequestCryptoSign)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	if a.keyStore.HasKey(cryptosignRequest.Realm(), cryptosignRequest.PublicKey()) {
		return auth.NewResponse("", "anonymous", 0)
	}

	return nil, fmt.Errorf("invalid credentials")
}

func (a *ServerAuthenticator) Realms() map[string][]string {
	return a.keyStore.keys
}
