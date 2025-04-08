package hash

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	Len = 60
)

// Encrypt 使用 bcrypt 对密码进行加密.
func Encrypt(password string, cost ...int) (string, error) {
	// GenerateFromPassword 的第二个参数是 cost 值。建议大于 12，数值越大耗费时间越长
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), passCost(cost...))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Verify 验证明文密码和数据库的哈希值.
//
//	password 明文密码.
//	hashedPassword 数据库的哈希值.
//
// 注意：如果密码是哈希过的数据，则需要先解密再验证.
func Verify(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// IsHashed 判断字符串是否是哈希过的数据.
func IsHashed(str string) bool {
	// bcrypt 加密后的长度等于 60
	return len(str) == Len
}

// Compare 对比明文密码和数据库的哈希值.
// hashedPassword 数据库的哈希值.
// password 明文密码.
func Compare(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// HashNeedRefresh 判断密码是否需要刷新.
func HashNeedRefresh(hashedPwd string, cost ...int) bool {
	hashCost, err := bcrypt.Cost([]byte(hashedPwd))
	return err != nil || hashCost != passCost(cost...)
}

func passCost(cost ...int) int {
	if len(cost) > 0 {
		if cost[0] > bcrypt.DefaultCost {
			return cost[0]
		}
	}
	return bcrypt.DefaultCost
}
