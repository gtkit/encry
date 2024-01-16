// @Author xiaozhaofu 2022/12/2 14:26:00
package rc4_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gtkit/encry/rc4"
)

func TestRc4(t *testing.T) {
	key := "officeaddin"
	str := "xiaozhaofu"
	// 加密
	s1, _ := rc4.New(key, []byte(str))
	// 解密
	s2, _ := rc4.New(key, s1)
	t.Log("s2 string----", str)
	assert.Equal(t, str, string(s2))
}
