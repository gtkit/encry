// Package mlkem 提供后量子密钥封装机制 ML-KEM-768（NIST FIPS 203，基于 crypto/mlkem）。
//
// 典型用法：接收方 GenerateKeyPair 得到 (decapSeed 私有, encapKey 公开)；发送方用
// encapKey Encapsulate 得到 (sharedSecret, ciphertext)，把 ciphertext 发给接收方；
// 接收方用 decapSeed 对 ciphertext Decapsulate 还原出相同的 sharedSecret。
// 得到的 sharedSecret（32 字节）通常再经 hkdf 派生为对称密钥。
package mlkem

import "crypto/mlkem"

// SharedKeySize 是共享密钥的字节长度。
const SharedKeySize = mlkem.SharedKeySize

// GenerateKeyPair 生成一对 ML-KEM-768 密钥，返回可序列化的
// 解封装种子（私有，须保密）与封装公钥（可公开传输）。
func GenerateKeyPair() (decapSeed, encapKey []byte, err error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}

// Encapsulate 用封装公钥产生一个共享密钥及其密文。
func Encapsulate(encapKey []byte) (sharedSecret, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapKey)
	if err != nil {
		return nil, nil, err
	}
	ss, ct := ek.Encapsulate()
	return ss, ct, nil
}

// Decapsulate 用解封装种子从密文还原共享密钥。
// 注意 ML-KEM 的隐式拒绝语义：对被篡改的密文不会报错，而是返回一个
// 确定性的、与发送方不一致的共享密钥。
func Decapsulate(decapSeed, ciphertext []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(decapSeed)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ciphertext)
}
