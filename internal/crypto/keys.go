package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"transmtf.com/oidc/internal/store"
)

const settingKey = "rsa_private_key"

type Keys struct {
	priv *rsa.PrivateKey
	kid  string
}

func LoadOrGenerate(ctx context.Context, st *store.Store) (*Keys, error) {
	pemStr := st.GetSetting(ctx, settingKey)
	if pemStr != "" {
		block, _ := pem.Decode([]byte(pemStr))
		if block != nil {
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return &Keys{priv: priv, kid: "1"}, nil
			}
		}
	}
	// Generate new key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err := st.SetSetting(ctx, settingKey, string(pemBytes)); err != nil {
		return nil, fmt.Errorf("save RSA key: %w", err)
	}
	return &Keys{priv: priv, kid: "1"}, nil
}

// SignIDToken issues a signed JWT ID token.
func (k *Keys) SignIDToken(issuer, subject, audience, nonce string, scopes []string, u *store.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            issuer,
		"sub":            subject,
		"aud":            audience,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"auth_time":      now.Unix(),
		"email_verified": true,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for _, sc := range scopes {
		switch sc {
		case "email":
			claims["email"] = u.Email
		case "profile":
			claims["name"]    = u.DisplayName
			claims["picture"] = u.AvatarURL
			claims["role"]    = u.Role
		}
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = k.kid
	return t.SignedString(k.priv)
}

// JWKSet returns the public key set for /.well-known/jwks.json.
func (k *Keys) JWKSet() map[string]any {
	pub := &k.priv.PublicKey
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": k.kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
