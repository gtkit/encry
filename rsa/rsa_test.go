package rsa

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

func TestRsa(t *testing.T) {
	// 生成密钥对
	err := GenerateRsaKey(1024, "./")
	if err != nil {
		fmt.Println(err)
	}
	// ----------------测试公钥加密 -----------
	plainText := []byte("https://go.microsoft.com/fwlink/?LinkID=529180&aid=5a19b55a-3ef3-41d2-98fa-668838fb3666")
	cipherText, err := RsaEncrypt(plainText, "./public.pem")
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Printf("加密后为:%s\n", cipherText)
	fmt.Println("------加密后------")
	str := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println("str-----", str)

	// -----------------测试 私钥解密----------
	plainText, err = RsaDecrypt(cipherText, "./private.pem")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("解密后为:%s\n", plainText)
}

func TestRsaEncrypt(t *testing.T) {
	// 测试使用私钥加密
	plainText := []byte("hi, I'm lady_killer9")
	cipherText, err := RsaEncrypt(plainText, "./private.pem")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("加密后为:%s\n", base64.StdEncoding.EncodeToString(cipherText))
}

/*
*
测试 rsa 签名和验签
*/
func TestSignVerify(t *testing.T) {
	plainText := []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来")
	signText, err := RsaSign(plainText, "./private.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	signstr := base64.StdEncoding.EncodeToString(signText)
	fmt.Printf("生成签名 signText-----%s\n", signstr)

	fmt.Println("---- 开始验签--------")
	// 解析签名
	data, _ := base64.StdEncoding.DecodeString(signstr)
	err = RsaVerify(plainText, "./public.pem", data)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("-----------验证成功----------")

	// plainText 与加签数据不同,应该验签失败
	plainText = []byte("张华考上了北京大学；李萍进了中等技术学校；我在百货公司当售货员：我们都有美好的未来！")
	// err = RsaVerify(plainText, "./public.pem", signText)
	err = RsaVerify(plainText, "./public.pem", data)
	if err != nil { // 注意处理 panic
		fmt.Println("----- 验签失败-----", err)
		os.Exit(0)
	}
}
