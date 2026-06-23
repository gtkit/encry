package rsa_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsa(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("https://go.microsoft.com/fwlink/?LinkID=529180&aid=5a19b55a-3ef3-41d2-98fa-668838fb3666")
	cipherText, err := rsa.Encrypt(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	plainText, err = rsa.Decrypt(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, "https://go.microsoft.com/fwlink/?LinkID=529180&aid=5a19b55a-3ef3-41d2-98fa-668838fb3666", string(plainText))
}

func TestRsaEncrypt(t *testing.T) {
	dir := generateRSAKeys(t)
	_, err := rsa.Encrypt([]byte("hi, I'm lady_killer9"), filepath.Join(dir, "private.pem"))
	require.Error(t, err)
}

/*
*
测试 rsa 签名和验签.
*/
func TestSignVerify(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来")
	signText, err := rsa.Sign(plainText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)

	require.NoError(t, rsa.Verify(plainText, filepath.Join(dir, "public.pem"), signText))

	// plainText 与加签数据不同,应该验签失败
	plainText = []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来！")
	require.Error(t, rsa.Verify(plainText, filepath.Join(dir, "public.pem"), signText))
}

func TestEncryptToBase64AndDecryptBase64(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("short-message")

	cipherText, err := rsa.EncryptToBase64(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestEncryptBlockRoundTrip(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte(strings.Repeat("block-data-", 80))

	cipherText, err := rsa.EncryptBlock(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptBlockBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestSignSHA256Base64(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("sign-sha256")

	signature, err := rsa.SignSHA256Base64(plainText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)

	require.NoError(t, rsa.VerifySHA256Base64(plainText, filepath.Join(dir, "public.pem"), signature))
}

func TestOAEPEncryptDecrypt(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("oaep-message")

	cipherText, err := rsa.EncryptOAEPBase64(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptOAEPBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestOAEPChunkedEncryptDecrypt(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte(strings.Repeat("oaep-block-", 80))

	cipherText, err := rsa.EncryptOAEPChunkedBase64(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptOAEPChunkedBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestPSSSignVerify(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("pss-message")

	signature, err := rsa.SignPSSBase64(plainText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)

	require.NoError(t, rsa.VerifyPSSBase64(plainText, filepath.Join(dir, "public.pem"), signature))
	require.Error(t, rsa.VerifyPSSBase64([]byte("wrong"), filepath.Join(dir, "public.pem"), signature))
}

func TestPKIXPublicKeyCompatibility(t *testing.T) {
	dir := t.TempDir()
	privateKey, publicKey, err := rsa.GenerateKeyPair(2048)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "private.pem"), rsa.MarshalPKCS1PrivateKeyPEM(privateKey), 0o600))
	pkixPublic, err := rsa.MarshalPKIXPublicKeyPEM(publicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "public.pem"), pkixPublic, 0o600))

	plainText := []byte("pkix-public-key")
	cipherText, err := rsa.Encrypt(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.Decrypt(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestSignCS8MD5Compatibility(t *testing.T) {
	dir := t.TempDir()
	privateKey, publicKey, err := rsa.GenerateKeyPair(2048)
	require.NoError(t, err)

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "private_pkcs8.pem"), privatePEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "public.pem"), rsa.MarshalPKCS1PublicKeyPEM(publicKey), 0o600))

	signature, err := rsa.SignCS8MD5("legacy-md5", filepath.Join(dir, "private_pkcs8.pem"))
	require.NoError(t, err)

	require.NoError(t, rsa.VerifyMD5("legacy-md5", signature, filepath.Join(dir, "public.pem")))
}

func generateRSAKeys(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, rsa.GenerateRsaKey(2048, dir))
	return dir
}
