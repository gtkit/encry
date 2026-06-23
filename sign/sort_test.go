package sign_test

import (
	"net"
	"testing"

	"github.com/gtkit/encry/md5"
	"github.com/gtkit/encry/sign"
	"github.com/stretchr/testify/require"
)

func TestSortByDicStringifyValueTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "string",
			data: map[string]any{"k": "v"},
			want: "k=v",
		},
		{
			name: "bytes",
			data: map[string]any{"k": []byte("bs")},
			want: "k=bs",
		},
		{
			name: "int",
			data: map[string]any{"k": -7},
			want: "k=-7",
		},
		{
			name: "int8",
			data: map[string]any{"k": int8(-8)},
			want: "k=-8",
		},
		{
			name: "int16",
			data: map[string]any{"k": int16(-16)},
			want: "k=-16",
		},
		{
			name: "int32",
			data: map[string]any{"k": int32(-32)},
			want: "k=-32",
		},
		{
			name: "int64",
			data: map[string]any{"k": int64(-64)},
			want: "k=-64",
		},
		{
			name: "uint",
			data: map[string]any{"k": uint(7)},
			want: "k=7",
		},
		{
			name: "uint8",
			data: map[string]any{"k": uint8(8)},
			want: "k=8",
		},
		{
			name: "uint16",
			data: map[string]any{"k": uint16(16)},
			want: "k=16",
		},
		{
			name: "uint32",
			data: map[string]any{"k": uint32(32)},
			want: "k=32",
		},
		{
			name: "uint64",
			data: map[string]any{"k": uint64(64)},
			want: "k=64",
		},
		{
			name: "float32",
			data: map[string]any{"k": float32(1.5)},
			want: "k=1.5",
		},
		{
			name: "float64",
			data: map[string]any{"k": 2.25},
			want: "k=2.25",
		},
		{
			name: "bool true",
			data: map[string]any{"k": true},
			want: "k=true",
		},
		{
			name: "bool false",
			data: map[string]any{"k": false},
			want: "k=false",
		},
		{
			// net.IP 实现 fmt.Stringer.
			name: "stringer",
			data: map[string]any{"k": net.IPv4(1, 2, 3, 4)},
			want: "k=1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, sign.SortByDic(tt.data, "&", "="))
		})
	}
}

func TestSortByDicSkipsAndUnsupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "nil value skipped",
			data: map[string]any{"a": nil, "b": "1"},
			want: "b=1",
		},
		{
			name: "empty string skipped",
			data: map[string]any{"a": "", "b": "1"},
			want: "b=1",
		},
		{
			name: "empty bytes skipped",
			data: map[string]any{"a": []byte{}, "b": "1"},
			want: "b=1",
		},
		{
			name: "unsupported type skipped",
			data: map[string]any{"a": []int{1, 2}, "b": "1"},
			want: "b=1",
		},
		{
			name: "all skipped yields empty",
			data: map[string]any{"a": nil, "b": ""},
			want: "",
		},
		{
			name: "ordered by key",
			data: map[string]any{"c": "3", "a": "1", "b": "2"},
			want: "a=1&b=2&c=3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, sign.SortByDic(tt.data, "&", "="))
		})
	}
}

func TestSortByDicDelimiterAndConnector(t *testing.T) {
	t.Parallel()

	data := map[string]any{"a": "1", "b": "2"}

	// 无 connector：key 与 value 直接拼接.
	require.Equal(t, "a1&b2", sign.SortByDic(data, "&"))

	// 空 connector 显式传入.
	require.Equal(t, "a1#b2", sign.SortByDic(data, "#", ""))

	// 空 delimiter：结尾无分隔符可修剪.
	require.Equal(t, "a=1b=2", sign.SortByDic(data, "", "="))

	// 多字符 delimiter 修剪.
	require.Equal(t, "a=1||b=2", sign.SortByDic(data, "||", "="))
}

func TestMapSign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		signStr   string
		appSecret string
	}{
		{"with secret", "a1&b2", "secret"},
		{"empty secret", "a1&b2", ""},
		{"empty sign str", "", "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := sign.MapSign(tt.signStr, tt.appSecret)

			// 与 MD5(secret+signStr+secret) 大写一致.
			want := md5.String(tt.appSecret + tt.signStr + tt.appSecret)
			want = upper(want)
			require.Equal(t, want, got)
			require.Len(t, got, 32)

			// 确定性.
			require.Equal(t, got, sign.MapSign(tt.signStr, tt.appSecret))
		})
	}

	// 不同密钥产生不同签名.
	require.NotEqual(t,
		sign.MapSign("a1&b2", "secret"),
		sign.MapSign("a1&b2", "other"),
	)
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
