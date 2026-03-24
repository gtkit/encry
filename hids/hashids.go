package hids

import (
	"errors"

	"github.com/speps/go-hashids"
)

var _ Hash = (*hash)(nil)

type Hash interface {
	i()

	// HashidsEncode 加密
	EncodeHashids(params []int) (string, error)

	// HashidsDecode 解密
	DecodeHashids(hash string) ([]int, error)
}

type hash struct {
	secret string
	length int
	ids    *hashids.HashID
	err    error
}

func New(secret string, length int) Hash {
	hd := hashids.NewData()
	hd.Salt = secret
	hd.MinLength = length
	ids, err := hashids.NewWithData(hd)

	return &hash{
		secret: secret,
		length: length,
		ids:    ids,
		err:    err,
	}
}

func (h *hash) EncodeHashids(params []int) (string, error) {
	if h.err != nil {
		return "", h.err
	}
	if h.ids == nil {
		return "", errors.New("hashids not initialized")
	}
	return h.ids.Encode(params)
}

func (h *hash) DecodeHashids(hash string) ([]int, error) {
	if h.err != nil {
		return nil, h.err
	}
	if h.ids == nil {
		return nil, errors.New("hashids not initialized")
	}
	return h.ids.DecodeWithError(hash)
}

func (h *hash) i() {}
