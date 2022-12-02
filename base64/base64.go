// @Author xiaozhaofu 2022/12/1 11:46:00
package base64

import (
	"encoding/base64"
)

// @Title Encode
// @Description 加密
// @Author xiaozhaofu 2022-12-01 12:00:22
// @Param data
// @Return string
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// @Title Decode
// @Description 解密
// @Author xiaozhaofu 2022-12-01 12:00:36
// @Param data
// @Return string
func Decode(data string) (str []byte, err error) {
	str, err = base64.StdEncoding.DecodeString(data)
	return
}
