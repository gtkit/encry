package sign

import (
	"strings"

	"github.com/gtkit/encry/hmac"
)

// MapSignHMAC 使用 HMAC-SHA256 对排序后的字符串参数生成签名，appSecret 作为密钥，
// 返回大写十六进制字符串。
//
// 相比 MapSign 的 MD5 同串拼接方案，HMAC-SHA256 抗碰撞更强、构造更标准，
// 新系统请优先使用本函数。
func MapSignHMAC(signStr, appSecret string) string {
	return strings.ToUpper(hmac.Sha256ToHex([]byte(appSecret), []byte(signStr)))
}
