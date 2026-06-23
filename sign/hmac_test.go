package sign_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gtkit/encry/sign"
	"github.com/stretchr/testify/require"
)

func TestMapSignHMAC(t *testing.T) {
	const (
		signStr   = "a1&b2&timestamp=1661947835"
		appSecret = "9aff19ba6e547159d9f1ecc3322fbb"
	)

	got := sign.MapSignHMAC(signStr, appSecret)

	// 确定性
	require.Equal(t, got, sign.MapSignHMAC(signStr, appSecret))

	// 与标准 HMAC-SHA256 hex 大写一致
	mac := hmac.New(sha256.New, []byte(appSecret))
	_, _ = mac.Write([]byte(signStr))
	want := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
	require.Equal(t, want, got)
	require.Len(t, got, 64)

	// 不同密钥结果不同
	require.NotEqual(t, got, sign.MapSignHMAC(signStr, appSecret+"x"))
}
