// @Author xiaozhaofu 2022/11/11 10:06:00
package rsa

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"runtime"
)

// GetKey 读取公钥/私钥文件，获取解码的pem块.
// filePath文件路径.
// 返回pem块和错误.
func GetKey(filePath string) (*pem.Block, error) {
	file, err := os.Open(filePath)
	defer func(f *os.File) {
		if ferr := f.Close(); err != nil {
			_, file, line, _ := runtime.Caller(0)
			log.Println(Error(file, line+1, ferr.Error()))
			return
		}
	}(file)

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

// Error 错误格式化.
func Error(file string, line int, err string) error {
	return fmt.Errorf("file:%s line:%d error:%s", file, line, err)
}
