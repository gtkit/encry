package cryptoenv

import (
	"cmp"
	"os"
	"path/filepath"
)

// KeyConfig 描述服务使用的密钥目录和当前生效 kid.
type KeyConfig struct {
	KeyDir    string
	ActiveKID string
}

// LoadKeyConfig 从环境变量加载密钥配置；未配置时创建一个临时根目录用于示例和本地运行.
func LoadKeyConfig(keyDirEnv, activeKIDEnv, tempPrefix, defaultSubdir, defaultKID string) (KeyConfig, func(), error) {
	if keyDir := os.Getenv(keyDirEnv); keyDir != "" {
		return KeyConfig{
			KeyDir:    keyDir,
			ActiveKID: cmp.Or(os.Getenv(activeKIDEnv), defaultKID),
		}, func() {}, nil
	}

	tempRoot, err := os.MkdirTemp("", tempPrefix)
	if err != nil {
		return KeyConfig{}, nil, err
	}

	return KeyConfig{
			KeyDir:    filepath.Join(tempRoot, defaultSubdir),
			ActiveKID: cmp.Or(os.Getenv(activeKIDEnv), defaultKID),
		}, func() {
			_ = os.RemoveAll(tempRoot)
		}, nil
}
