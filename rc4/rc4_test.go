// @Author xiaozhaofu 2022/12/2 14:26:00
package rc4_test

import (
	"testing"

	"github.com/gtkit/encry/rc4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRC4ErrorPaths(t *testing.T) {
	// 空 key 会让底层 NewCipher 报错，覆盖各函数的错误分支。
	_, err := rc4.Apply("", []byte("data"))
	require.Error(t, err)

	require.Error(t, rc4.ApplyInPlace("", []byte("data")))

	_, err = rc4.EncryptToBase64("", []byte("data"))
	require.Error(t, err)

	_, err = rc4.EncryptStringToBase64("", "data")
	require.Error(t, err)

	// 非法 Base64 触发 DecryptFromBase64 的解码错误分支。
	_, err = rc4.DecryptFromBase64("key", "%%%not-base64%%%")
	require.Error(t, err)

	_, err = rc4.DecryptBase64ToString("key", "%%%not-base64%%%")
	require.Error(t, err)
}

func TestRc4(t *testing.T) {
	key := "officeaddin"
	str := "xiaozhaofu"
	// 加密
	s1, _ := rc4.Apply(key, []byte(str))
	// 解密
	s2, _ := rc4.Apply(key, s1)
	t.Log("s2 string----", str)
	assert.Equal(t, str, string(s2))
}

func TestRC4DoesNotMutateInput(t *testing.T) {
	key := "officeaddin"
	src := []byte("xiaozhaofu")
	original := append([]byte(nil), src...)

	encrypted, err := rc4.Apply(key, src)
	require.NoError(t, err)

	assert.Equal(t, original, src)
	assert.NotEqual(t, original, encrypted)
}

func TestRC4Base64RoundTrip(t *testing.T) {
	key := "officeaddin"
	plainText := "hello-rc4"

	cipherText, err := rc4.EncryptStringToBase64(key, plainText)
	require.NoError(t, err)

	decrypted, err := rc4.DecryptBase64ToString(key, cipherText)
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}
