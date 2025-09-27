package wampshell

import (
	"context"
	"sync"

	"github.com/xconnio/berncrypt/go"
	"github.com/xconnio/xconn-go"
)

type KeyPair struct {
	Send    []byte
	Receive []byte
}

type EncryptionManager struct {
	session *xconn.Session

	keys map[uint64]*KeyPair

	sync.Mutex
}

func NewEncryptionManager(session *xconn.Session) *EncryptionManager {
	return &EncryptionManager{
		session: session,
		keys:    make(map[uint64]*KeyPair),
	}
}

func (e *EncryptionManager) Setup() error {
	response := e.session.Register("wampshell.key.exchange", e.HandleKeyExchange).Do()
	if response.Err != nil {
		return response.Err
	}

	response = e.session.Register("wampshell.payload.echo", e.TestEcho).Do()
	if response.Err != nil {
		return response.Err
	}

	return nil
}

func (e *EncryptionManager) HandleKeyExchange(_ context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
	publicKeyPeer, err := invocation.ArgBytes(0)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
	}

	publicKey, privateKey, err := berncrypt.CreateX25519KeyPair()
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	sharedSecret, err := berncrypt.PerformKeyExchange(privateKey, publicKeyPeer)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	sendKey, err := berncrypt.DeriveKeyHKDF(sharedSecret, []byte("backendToFrontend"))
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	receiveKey, err := berncrypt.DeriveKeyHKDF(sharedSecret, []byte("frontendToBackend"))
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	sessionID := invocation.Caller()

	e.Lock()
	e.keys[sessionID] = &KeyPair{Send: sendKey, Receive: receiveKey}
	e.Unlock()

	return xconn.NewInvocationResult(publicKey)
}

func (e *EncryptionManager) TestEcho(_ context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
	payload, err := invocation.ArgBytes(0)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
	}

	e.Lock()
	key, ok := e.keys[invocation.Caller()]
	e.Unlock()

	if !ok {
		return xconn.NewInvocationError("wamp.error.unavailable", "unavailable")
	}

	decryptedPayload, err := berncrypt.DecryptChaCha20Poly1305(payload[12:], payload[:12], key.Receive)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(decryptedPayload, key.Send)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	response := make([]byte, len(nonce)+len(ciphertext))
	copy(response, nonce)
	copy(response[len(nonce):], ciphertext)
	return xconn.NewInvocationResult(response)
}

func (e *EncryptionManager) Keys() map[uint64]*KeyPair {
	return e.keys
}

func (e *EncryptionManager) Key(sessionID uint64) (*KeyPair, bool) {
	e.Lock()
	defer e.Unlock()
	key, ok := e.keys[sessionID]
	return key, ok
}
