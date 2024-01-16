// @Author xiaozhaofu 2023/7/15 18:38:00
package rsa

import (
	"crypto"
	"crypto/md5" //nolint:gosec //used
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"log"
	"runtime"
)

// Sign Rsa签名.
// plainText 明文.
// filePath 私钥文件路径.
// 返回签名后的数据 错误.
func Sign(plainText []byte, priFilePath string) ([]byte, error) {
	// get pem.Block
	block, err := GetKey(priFilePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	// calculate hash value
	hashText := sha512.Sum512(plainText)
	// Sign with hashText
	signText, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA512, hashText[:])
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	return signText, nil
}

// Verify Rsa签名验证.
// plainText 明文.
// filePath 公钥文件路径..
// 返回签名后的数据 错误.
func Verify(plainText []byte, pubFilePath string, signText []byte) error {
	// get pem.Block
	block, err := GetKey(pubFilePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	// x509
	pubInter, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	pubKey, ok := pubInter.(*rsa.PublicKey)
	if !ok {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, "非 rsa.PublicKey 指针类型")
	}
	// hashText to verify
	hashText := sha512.Sum512(plainText)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashText[:], signText)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	return nil
}

// SignCS8MD5 计算签名 PKCS8 MD5.
// plainText 明文, 参数字典排序后的字符串.
// priKey 私钥.
func SignCS8MD5(plainText, priFilePath string) (string, error) {
	block, err := GetKey(priFilePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}

	hashMd5 := md5.Sum([]byte(plainText)) //nolint:gosec //used
	hashText := hashMd5[:]

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}
	pri, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		signature, signerr := rsa.SignPKCS1v15(rand.Reader, pri, crypto.MD5, hashText)
		if signerr != nil {
			_, file, line, _ := runtime.Caller(0)
			return "", Error(file, line+1, signerr.Error())
		}
		return base64.StdEncoding.EncodeToString(signature), signerr
	}

	_, file, line, _ := runtime.Caller(0)
	return "", Error(file, line+1, "private key error")
}

// VerifyMD5 验证签名 PKCS8 MD5.
// plainText 明文, 参数字典排序后的字符串.
// sign 签名.
// pubFilePath 公钥 路径.
func VerifyMD5(plainText, sign, pubFilePath string) error {
	// block, _ := pem.Decode([]byte(pubkey))
	block, berr := GetKey(pubFilePath)
	if berr != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, berr.Error())
	}
	pubInter, perr := x509.ParsePKIXPublicKey(block.Bytes)
	if perr != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, perr.Error())
	}
	pub, ok := pubInter.(*rsa.PublicKey)
	if !ok {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, "非 rsa.PublicKey 指针类型")
	}

	hashMd5 := md5.Sum([]byte(plainText)) //nolint:gosec //used
	decodedSign, decerr := base64.StdEncoding.DecodeString(sign)
	if decerr != nil {
		log.Println("decode sign error: ", decerr)
		return decerr
	}

	err := rsa.VerifyPKCS1v15(pub, crypto.MD5, hashMd5[:], decodedSign)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	return nil
}
