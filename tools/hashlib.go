package tools

import (
	"crypto/sha256"
	"fmt"
)

func SHA224String(password string) string {
	hash := sha256.New224()
	hash.Write([]byte(password))
	val := hash.Sum(nil)
	str := ""
	for _, v := range val {
		str += fmt.Sprintf("%02x", v)
	}
	return str
}
func GenerateRandomString(length int) string {
	// 定义字符集
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 生成随机字符串
	randomString := make([]byte, length)
	for i := range randomString {
		randomString[i] = charset[i%len(charset)]
	}
	return string(randomString)
}
