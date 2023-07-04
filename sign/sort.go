// @Author xiaozhaofu 2023/3/20 17:47:00
package sign

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// SortByDic 字典排序, map[string]interface{} 类型
func SortByDic(data map[string]interface{}, delimiter ...string) string {
	keys := make([]string, 0, len(data))

	for k, _ := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	// 按照排序后的key遍历map
	for _, k := range keys {
		if data[k] == "" {
			continue
		}
		buf.WriteString(k)
		switch vv := data[k].(type) {
		case string:
			buf.WriteString(vv)
		case int:
			buf.WriteString(strconv.FormatInt(int64(vv), 10))
		case int8:
		case int16:
		case int32:
		case int64:
			buf.WriteString(strconv.FormatInt(vv, 10))
		default:
			continue
		}
		if len(delimiter) > 0 {
			buf.WriteString(delimiter[0])
		}
	}
	return buf.String()
}

// map 参数获取 sign
func MapSign(signParams, appSecret string) string {

	var buf bytes.Buffer

	buf.WriteString(appSecret)

	buf.WriteString(signParams)

	buf.WriteString(appSecret)

	returnStr := buf.String()
	// fmt.Println("------------return str : ", returnStr)

	s := NewMd5(returnStr)

	return strings.ToUpper(s)
}
func NewMd5(str string) string {
	md5ctx := md5.New()
	md5ctx.Write([]byte(str))

	return hex.EncodeToString(md5ctx.Sum(nil))
}
