// @Author xiaozhaofu 2023/3/20 17:47:00
package sign

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gtkit/encry/md5"
)

// SortByDic 字典排序, map[string]any 类型.
// delimiter 分隔符, 每组kv之间的分隔符, 一般为&.
// connector 连接符, key和value连接, 一般为 = 号.
func SortByDic(data map[string]any, delimiter string, connector ...string) string {
	keys := slices.Sorted(maps.Keys(data))

	connectorStr := ""
	if len(connector) > 0 {
		connectorStr = connector[0]
	}

	var buf bytes.Buffer
	for _, k := range keys {
		value, ok := stringifyValue(data[k])
		if !ok || value == "" {
			continue
		}
		buf.WriteString(k)
		if connectorStr != "" {
			buf.WriteString(connectorStr)
		}
		buf.WriteString(value)
		if delimiter != "" {
			buf.WriteString(delimiter)
		}
	}
	return strings.TrimSuffix(buf.String(), delimiter)
}

func stringifyValue(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "", false
	case string:
		return v, true
	case []byte:
		return string(v), true
	case int:
		return strconv.FormatInt(int64(v), 10), true
	case int8:
		return strconv.FormatInt(int64(v), 10), true
	case int16:
		return strconv.FormatInt(int64(v), 10), true
	case int32:
		return strconv.FormatInt(int64(v), 10), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint:
		return strconv.FormatUint(uint64(v), 10), true
	case uint8:
		return strconv.FormatUint(uint64(v), 10), true
	case uint16:
		return strconv.FormatUint(uint64(v), 10), true
	case uint32:
		return strconv.FormatUint(uint64(v), 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	case fmt.Stringer:
		return v.String(), true
	default:
		return "", false
	}
}

// MapSign map 排序后字符串参数获取 sign.
//
// 注意：本函数使用 MD5（appSecret 同串前后拼接），抗碰撞已较弱，仅为兼容旧系统保留。
// 新系统请使用 MapSignHMAC（HMAC-SHA256）。
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
