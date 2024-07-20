package pass

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	COST = 12
	Len  = 60
)

// Hash 使用 bcrypt 对密码进行加密.
func HashMake(password string, cost ...int) (string, error) {
	// GenerateFromPassword 的第二个参数是 cost 值。建议大于 12，数值越大耗费时间越长
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), passCost(cost...))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Check 对比明文密码和数据库的哈希值.
func Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// IsHashed 判断字符串是否是哈希过的数据.
func IsHashed(str string) bool {
	// bcrypt 加密后的长度等于 60
	return len(str) == Len
}

// Compare 对比明文密码和数据库的哈希值.
func Compare(e string, p string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(e), []byte(p))
	if err != nil {
		return false, err
	}
	return true, nil
}

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
