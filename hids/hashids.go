package hids

import (
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
}

func New(secret string, length int) Hash {
	return &hash{
		secret: secret,
		length: length,
	}
}

func (h *hash) EncodeHashids(params []int) (string, error) {
	hd := hashids.NewData()
	hd.Salt = h.secret
	hd.MinLength = h.length

	hashStr, err := hashids.NewWithData(hd)
	if err != nil {
		return "", err
	}
	enhashStr, err := hashStr.Encode(params)
	if err != nil {
		return "", err
	}

	return enhashStr, nil
}

func (h *hash) DecodeHashids(hash string) ([]int, error) {
	hd := hashids.NewData()
	hd.Salt = h.secret
	hd.MinLength = h.length

	ids, err := hashids.NewWithData(hd)

	if err != nil {
		return nil, err
	}
	deids, err := ids.DecodeWithError(hash)
	if err != nil {
		return nil, err
	}
	return deids, nil
}

func (h *hash) i() {}
