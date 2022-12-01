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
func Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// @Title Decode
// @Description 解密
// @Author xiaozhaofu 2022-12-01 12:00:36
// @Param data
// @Return string
func Decode(data string) string {
	str, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "base64 解码错误：" + err.Error()
	}
	return string(str)
}
