package hmac

import (
	"crypto/hmac"
	"crypto/sha1"

	"gitlab.superjq.com/go-tools/encry/base64"
)

func Sha1(keyStr, value string) string {
	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	return base64.Encode(mac.Sum(nil))
}
