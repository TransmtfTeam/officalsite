package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpStep   = 30
)

func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func buildTOTPUri(issuer, account, secret string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" {
		issuer = "TeamTransMTF"
	}
	if account == "" {
		account = "user"
	}
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

func verifyTOTP(secret, code string, now time.Time) bool {
	secret = strings.TrimSpace(secret)
	code = normalizeOTPCode(code)
	if secret == "" || len(code) != totpDigits {
		return false
	}

	for drift := -1; drift <= 1; drift++ {
		step := now.Unix()/totpStep + int64(drift)
		expect, err := totpAtStep(secret, step)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expect)) == 1 {
			return true
		}
	}
	return false
}

func totpAtStep(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := int32(sum[offset]&0x7f)<<24 |
		int32(sum[offset+1])<<16 |
		int32(sum[offset+2])<<8 |
		int32(sum[offset+3])
	mod := int32(1_000_000)
	otp := int(binCode % mod)
	return fmt.Sprintf("%06d", otp), nil
}

func normalizeOTPCode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	return code
}
