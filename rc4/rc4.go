// @Author xiaozhaofu 2022/12/1 11:12:00
package rc4

import (
	"crypto/rc4"
)

// @Title New
// @Description rc4 加密和解密方法，都用此方法
// @Author xiaozhaofu 2022-12-01 11:29:44
// @Param key
// @Param str
// @Return string
func New(key string, str []byte) ([]byte, error) {
	c, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	c.XORKeyStream(str, str)
	return str, nil
}
