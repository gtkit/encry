package hash_test

import (
	"fmt"

	"github.com/gtkit/encry/hash"
)

// 零配置：一个参数即可生成并校验密码哈希.
func ExampleArgon2HashPassword() {
	encoded, err := hash.Argon2HashPassword("s3cr3t")
	if err != nil {
		panic(err)
	}

	fmt.Println(hash.Argon2VerifyPassword("s3cr3t", encoded))
	fmt.Println(hash.Argon2VerifyPassword("wrong", encoded))
	// Output:
	// true
	// false
}

// 高级用法：用 Functional Options 定制参数.
func ExampleNewArgon2() {
	a := hash.NewArgon2(
		hash.WithMemory(32*1024), // 32MB
		hash.WithTime(2),
	)

	encoded, err := a.Hash("s3cr3t")
	if err != nil {
		panic(err)
	}

	fmt.Println(a.Verify("s3cr3t", encoded))
	// Output: true
}
