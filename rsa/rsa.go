// @Author xiaozhaofu 2022/11/11 10:06:00
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

/**
公钥加密-分段
*/
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

	// keySize, srcSize := publicKey.Size(), len(src)
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
	bytesEncrypt = base64.StdEncoding.EncodeToString(buffer.Bytes())
	return
}

/**
私钥解密-分段
*/
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

// 读取公钥/私钥文件，获取解码的pem块
// filePath文件路径
// 返回pem块和错误
func GetKey(filePath string) (*pem.Block, error) {
	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}

	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, Error(file, line+1, err.Error())
	}

	block, _ := pem.Decode(buf)

	return block, err
}

// RSA是算法，ECB是分块模式，PKCS1Padding是填充模式
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
		Type:  "rsa private key",
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
		Type:  "rsa public key",
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

// 错误格式化
func Error(file string, line int, err string) error {
	return fmt.Errorf("file:%s line:%d error:%s", file, line, err)
}
