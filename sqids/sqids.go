// Package sqids 基于 sqids（hashids 的官方继任者）提供数字序列与短混淆字符串的可逆编解码。
package sqids

import (
	sqids "github.com/sqids/sqids-go"
)

// Hash 提供数字序列的编码与解码能力。
type Hash interface {
	// Encode 将一组无符号整数编码为混淆字符串。
	Encode(nums []uint64) (string, error)
	// Decode 将混淆字符串还原为原始整数序列；非法输入返回空切片。
	Decode(s string) []uint64
}

// Option 用于定制 sqids 参数（Functional Options）。
type Option func(*sqids.Options)

// WithAlphabet 设置自定义字母表（充当 hashids 中 salt 的角色）。
func WithAlphabet(alphabet string) Option {
	return func(o *sqids.Options) { o.Alphabet = alphabet }
}

// WithMinLength 设置输出的最小长度。
func WithMinLength(n uint8) Option {
	return func(o *sqids.Options) { o.MinLength = n }
}

// WithBlocklist 设置需要规避的词表（避免编码结果出现这些子串）。
func WithBlocklist(blocklist []string) Option {
	return func(o *sqids.Options) { o.Blocklist = blocklist }
}

type hash struct {
	s *sqids.Sqids
}

// New 创建编解码实例。
//
// 不传任何选项时使用 sqids 的默认字母表与默认 blocklist。
// 一旦传入任意选项，blocklist 默认为空（需要时用 WithBlocklist 指定），
// 未指定的 Alphabet/MinLength 仍回落到 sqids 默认值。
// 选项非法（如字母表过短、含重复或多字节字符）时返回错误。
func New(opts ...Option) (Hash, error) {
	if len(opts) == 0 {
		s, err := sqids.New()
		if err != nil {
			return nil, err
		}
		return &hash{s: s}, nil
	}

	var o sqids.Options
	for _, opt := range opts {
		opt(&o)
	}
	s, err := sqids.New(o)
	if err != nil {
		return nil, err
	}
	return &hash{s: s}, nil
}

// Encode 实现 Hash。
func (h *hash) Encode(nums []uint64) (string, error) {
	return h.s.Encode(nums)
}

// Decode 实现 Hash。
func (h *hash) Decode(s string) []uint64 {
	return h.s.Decode(s)
}
