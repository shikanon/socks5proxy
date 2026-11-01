// Package session provides authentication shared by desktop and mobile clients.
package session

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"time"

	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type Options struct{ IPv6 bool }

func Connect(ctx context.Context, serverAddr, clientID, token, obfs string, tlsConfig *tls.Config, kind string, control transport.SocketControl, options ...Options) (result transport.Conn, response protocol.Message, cipher protocol.Cipher, err error) {
	ipv6 := len(options) > 0 && options[0].IPv6
	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	defer authCancel()
	conn, err := transport.DialTunnelWithControl(authCtx, serverAddr, tlsConfig, kind, control)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	authConn := conn
	stop := context.AfterFunc(authCtx, func() { _ = authConn.CloseWithError(1, "authentication canceled") })
	defer func() {
		stopped := stop()
		if err != nil || !stopped || authCtx.Err() != nil {
			_ = conn.CloseWithError(1, "authentication failed")
			if err == nil {
				result, err = nil, authCtx.Err()
				if err == nil {
					err = context.Canceled
				}
			}
		}
	}()
	stream, err := conn.OpenControl(authCtx)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	deadline, _ := authCtx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	request := protocol.Message{
		Type: protocol.TypeAuthRequest, Version: protocol.Version,
		ClientID: clientID, Token: token, Obfs: obfs,
		IPv6: ipv6,
	}
	challenge := ""
	key := sha256.Sum256([]byte(token))
	obfsKey := token
	isTCP := kind == "tcp" || kind == "tcp-plain" || kind == "tcp-table"
	if isTCP {
		msg, err := protocol.ReadMessage(stream)
		if err != nil {
			return nil, protocol.Message{}, nil, err
		}
		if msg.Type != protocol.TypeAuthChallenge || !protocol.ValidNonce(msg.Nonce) {
			return nil, protocol.Message{}, nil, errors.New("invalid authentication challenge")
		}
		challenge = msg.Nonce
		request.Token = ""
		request.Nonce, err = protocol.NewNonce()
		if err != nil {
			return nil, protocol.Message{}, nil, err
		}
		request.Proof = protocol.AuthProof(key, protocol.ClientProofRole, challenge, request.Nonce, request)
		obfsKey = hex.EncodeToString(key[:])
	}
	if err := protocol.WriteMessage(stream, request); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	response, err = protocol.ReadMessage(stream)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	if response.Type == protocol.TypeError {
		return nil, protocol.Message{}, nil, errors.New(response.Error)
	}
	if response.Version != protocol.Version || response.Type != protocol.TypeAuthResponse || response.Obfs != obfs {
		return nil, protocol.Message{}, nil, errors.New("server returned invalid authentication response")
	}
	if isTCP && !protocol.VerifyAuthProof(key, protocol.ServerProofRole, challenge, request.Nonce, response) {
		return nil, protocol.Message{}, nil, errors.New("invalid server authentication proof")
	}
	if _, _, _, err := protocol.ValidateIPv6Parameters(response, ipv6); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	cipher, err = tunnel.NewObfuscator(obfs, obfsKey)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	if ipv6 && !isTCP {
		conn = transport.WithFragmentation(conn)
	}
	return conn, response, cipher, nil
}

// ConnectTable uses the shared table as the credential and daily data mapping.
func ConnectTable(ctx context.Context, serverAddr, clientID string, table *keytable.Table, control transport.SocketControl, options ...Options) (transport.Conn, protocol.Message, protocol.Cipher, error) {
	conn, response, cipher, err := Connect(ctx, serverAddr, clientID, table.Credential(), "none", nil, "tcp-table", control, options...)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	return transport.WithTable(conn, table), response, cipher, nil
}
