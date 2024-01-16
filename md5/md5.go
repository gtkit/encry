// @Author xiaozhaofu 2022/11/11 10:04:00
package md5

import (
	"crypto/md5" //nolint:gosec //used
	"encoding/hex"
)

// New 返回一个32位md5加密后的字符串.
func New(str string) string {
	h := md5.New() //nolint:gosec //used
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
