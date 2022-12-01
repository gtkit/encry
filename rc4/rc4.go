// @Author xiaozhaofu 2022/12/1 11:12:00
package rc4

import (
	"crypto/rc4"
)

func New(key, str string) string {
	c, _ := rc4.NewCipher([]byte(key))
	src := []byte(str)
	c.XORKeyStream(src, src)
	return string(src)
}
