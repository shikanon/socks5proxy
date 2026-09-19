package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	ClientProofRole = "socks5proxy-tcp-client/1"
	ServerProofRole = "socks5proxy-tcp-server/1"
)

func NewNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func ValidNonce(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// AuthProof binds the complete message and both fresh nonces to its role.
// The token digest is a credential-equivalent key and is never transmitted.
func AuthProof(key [sha256.Size]byte, role, challenge, nonce string, msg Message) string {
	msg.Proof = ""
	msg.Token = ""
	payload, _ := json.Marshal(struct {
		Role      string
		Challenge string
		Nonce     string
		Message   Message
	}{role, challenge, nonce, msg})
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyAuthProof(key [sha256.Size]byte, role, challenge, nonce string, msg Message) bool {
	if !ValidNonce(challenge) || !ValidNonce(nonce) || msg.Token != "" {
		return false
	}
	actual, err := hex.DecodeString(msg.Proof)
	if err != nil || len(actual) != sha256.Size {
		return false
	}
	expected, _ := hex.DecodeString(AuthProof(key, role, challenge, nonce, msg))
	return hmac.Equal(actual, expected)
}
