// @Author xiaozhaofu 2023/7/15 18:30:00
package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
)

// GenerateRsaKey RSA是算法，ECB是分块模式，PKCS1Padding是填充模式
// 整个构成一个完整的加密算法
// 生成RSA密钥对
// keySize 密钥大小
// dirPath 密钥对文件路径
// 返回错误
func GenerateRsaKey(keySize int, dirPath string) error {
	// ---------------------------- get  privateKey
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	// x509
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	// pem Block
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derText,
	}
	// just joint, caller must let dirPath right
	file, err := os.Create(dirPath + "private.pem")
	defer file.Close()
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	err = pem.Encode(file, block)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}

	// -------------------------- get PublicKey from privateKey
	publicKey := privateKey.PublicKey

	// PKCS#8编码 生成的 publickey
	derStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}

	// PKCS#1编码生成 publickey
	// derStream := x509.MarshalPKCS1PublicKey(&publicKey)

	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derStream,
	}
	file, err = os.Create(dirPath + "public.pem")
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	err = pem.Encode(file, block)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return Error(file, line+1, err.Error())
	}
	return nil
}

// RsaEncryptBlock 公钥加密-分段
// src 待加密的数据
// filePath 公钥文件路径
func RsaEncryptBlock(src []byte, filePath string) (bytesEncrypt string, err error) {

	block, err := GetKey(filePath)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	// 该断言表达式会返回 x 的值（也就是 value）和一个布尔值（也就是 ok）
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}

	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return "", Error(file, line+1, err.Error())
	}

	keySize, srcSize := pub.Size(), len(src)

	// 单次加密的长度需要减掉padding的长度，PKCS1为11
	offSet, once := 0, keySize-11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 加密一部分
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, pub, src[offSet:endIndex])
		if err != nil {
			_, file, line, _ := runtime.Caller(0)
			return "", Error(file, line+1, err.Error())
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	// 由于加密后是字节流，直接输出查看会乱码，因此，为了便于语言直接加解密，这里将加密之后的数据进行base64编码,. 输出加密好并base64编码的串，可用于其他语言解密
	bytesEncrypt = base64.StdEncoding.EncodeToString(buffer.Bytes())
	return
}

// RsaDecryptBlock 私钥解密-分段
// src 待解密的数据
// filePath 私钥文件路径
func RsaDecryptBlock(src []byte, filePath string) (bytesDecrypt []byte, err error) {
	// block, _ := pem.Decode(privateKeyBytes)
	// 或者读取文件
	block, err := GetKey(filePath)
	if err != nil {
		fmt.Println("getkey error:", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	keySize := privateKey.Size()
	srcSize := len(src)
	// log.Println("密钥长度：", keySize, "\t密文长度：\t", srcSize)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesDecrypt = buffer.Bytes()
	return
}

// RsaEncrypt Rsa公钥加密
// plainText 明文
// filePath 公钥文件路径
// 返回加密后的结果 错误
func RsaEncrypt(plainText []byte, filePath string) ([]byte, error) {
	// get pem.Block
	block, err := GetKey(filePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	// X509
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	publicKey, flag := publicInterface.(*rsa.PublicKey)
	if flag == false {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, "error occur when trans to *rsa.Publickey")
	}
	// encrypt
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	return cipherText, nil
}

// RsaDecrypt Rsa私钥解密
// cipherText 密文
// filePath 私钥文件路径
// 返回解密后的结果 错误
func RsaDecrypt(cipherText []byte, filePath string) (plainText []byte, err error) {
	// get pem.Block
	block, err := GetKey(filePath)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	// get privateKey
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// get plainText use privateKey
	plainText, err3 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err3 != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err3.Error())
	}
	return plainText, err
}
