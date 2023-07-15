// @Author xiaozhaofu 2023/7/15 18:38:00
package rsa

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"runtime"
)

// RsaSign Rsa签名
// plainText 明文
// filePath 私钥文件路径
// 返回签名后的数据 错误
func RsaSign(plainText []byte, priFilePath string) ([]byte, error) {
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

// RsaVerify Rsa签名验证
// plainText 明文
// filePath 公钥文件路径
// 返回签名后的数据 错误
func RsaVerify(plainText []byte, pubFilePath string, signText []byte) error {
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
	pubKey := pubInter.(*rsa.PublicKey)
	// hashText to verify
	hashText := sha512.Sum512(plainText)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashText[:], signText)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	return nil
}

// RsaSignCS8MD5 计算签名 PKCS8 MD5
// plainText 明文, 参数字典排序后的字符串
// priKey 私钥
func RsaSignCS8MD5(plainText, priFilePath string) (string, error) {
	block, err := GetKey(priFilePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}

	hashMd5 := md5.Sum([]byte(plainText))
	hashText := hashMd5[:]

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}
	pri, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		signature, err := rsa.SignPKCS1v15(rand.Reader, pri, crypto.MD5, hashText)
		if err != nil {
			_, file, line, _ := runtime.Caller(0)
			return "", Error(file, line+1, err.Error())
		}
		return base64.StdEncoding.EncodeToString(signature), err
	}

	_, file, line, _ := runtime.Caller(0)
	return "", Error(file, line+1, "private key error")
}

// RsaVerifyMD5 Rsa签名验证 PKCS8
// plainText 明文, 参数字典排序后的字符串
// sign 签名
// pubFilePath 公钥 路径

func RsaVerifyMD5(plainText, sign, pubFilePath string) error {
	// block, _ := pem.Decode([]byte(pubkey))
	block, err := GetKey(pubFilePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	pubInter, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	pub := pubInter.(*rsa.PublicKey)

	hashMd5 := md5.Sum([]byte(plainText))
	hashText := hashMd5[:]

	decodedSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		fmt.Println("-----decode sign error: ", err)
		return err
	}

	err = rsa.VerifyPKCS1v15(pub, crypto.MD5, hashText[:], decodedSign)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	return nil

}
