// @Author xiaozhaofu 2022/12/1 11:46:00
package base64

import (
	"encoding/base64"
)

/*
编码方式			说明
StdEncoding		常规编码
URLEncoding		URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /
RawStdEncoding	常规编码，末尾不补 =
RawURLEncoding	URL safe 编码，末尾不补 =
*/

// Encode @Title Encode
// @Description 加密
// @Author xiaozhaofu 2022-12-01 12:00:22
// @Param data
// @Return string
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// StdEncode 常规编码
func StdEncode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode @Title Decode
// @Description 解密
// @Param data
// @Return string
func Decode(data string) (str []byte, err error) {
	return base64.StdEncoding.DecodeString(data)
}

// StdDecode 常规编码
func StdDecode(data string) (str []byte, err error) {
	return base64.StdEncoding.DecodeString(data)
}

// UrlEncode URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /
func UrlEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// UrlDecode URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /
func UrlDecode(data string) (str []byte, err error) {
	return base64.URLEncoding.DecodeString(data)
}

// RawStdEncode 常规编码，末尾不补 =
func RawStdEncode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// RawStdDecode 常规编码，末尾不补 =
func RawStdDecode(data string) (str []byte, err error) {
	return base64.RawStdEncoding.DecodeString(data)
}

// RawUrlEncode URL safe 编码，末尾不补 =
func RawUrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// RawUrlDecode URL safe 编码，末尾不补 =
func RawUrlDecode(data string) (str []byte, err error) {
	return base64.RawURLEncoding.DecodeString(data)
}
