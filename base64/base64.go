// @Author xiaozhaofu 2022/12/1 11:46:00

// Package base64 提供 Base64 编解码的便捷封装（标准库 encoding/base64），
// 覆盖 Std/URL/RawStd/RawURL 四种编码。注意：Base64 只是编码，不是加密。
//
// 本包基本是标准库的一层薄封装；新代码直接用 encoding/base64 亦可。
// v2 可能收敛或移除本包，届时见版本变更说明。
package base64

import (
	"encoding/base64"
)

/*
编码方式			说明.
StdEncoding		常规编码
URLEncoding		URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /
RawStdEncoding	常规编码，末尾不补 =
RawURLEncoding	URL safe 编码，末尾不补 =
*/

// StdEncode 常规编码（注意：Base64 只是编码，不是加密）.
func StdEncode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// StdDecode 常规编码.
func StdDecode(data string) (str []byte, err error) {
	return base64.StdEncoding.DecodeString(data)
}

// URLEncode URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /.
func URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// URLDecode URL safe 编码，相当于替换掉字符串中的特殊字符，+ 和 /.
func URLDecode(data string) (str []byte, err error) {
	return base64.URLEncoding.DecodeString(data)
}

// RawStdEncode 常规编码，末尾不补 =.
func RawStdEncode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// RawStdDecode 常规编码，末尾不补 =.
func RawStdDecode(data string) (str []byte, err error) {
	return base64.RawStdEncoding.DecodeString(data)
}

// RawURLEncode URL safe 编码，末尾不补 =.
func RawURLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// RawURLDecode URL safe 编码，末尾不补 =.
func RawURLDecode(data string) (str []byte, err error) {
	return base64.RawURLEncoding.DecodeString(data)
}
