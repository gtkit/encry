// @Author xiaozhaofu 2023/3/20 17:47:00
package sign

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/gtkit/encry/md5"
)

// SortByDic 字典排序, map[string]interface{} 类型.
// delimiter 分隔符, 每组kv之间的分隔符, 一般为&.
// connector 连接符, key和value连接, 一般为 = 号.
func SortByDic(data map[string]interface{}, delimiter, connector string) string {
	keys := make([]string, 0, len(data))

	for k := range data {
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
		if connector != "" {
			buf.WriteString(connector)
		}
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
			buf.WriteString(delimiter)
		}
	}
	return strings.TrimRight(buf.String(), delimiter)
}

// MapSign map 排序后字符串参数获取 sign.
func MapSign(signStr, appSecret string) string {
	var buf bytes.Buffer
	if appSecret != "" {
		buf.WriteString(appSecret)
	}

	buf.WriteString(signStr)

	if appSecret != "" {
		buf.WriteString(appSecret)
	}

	returnStr := buf.String()

	s := md5.New(returnStr)
	return strings.ToUpper(s)
}
