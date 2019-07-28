package utils

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
)

// HashMD5 returns MD5 hash of the file
func HashMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	//noinspection GoUnhandledErrorResult
	defer file.Close()

	hash := md5.New()
	//Copy the file in the hash interface
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	hashInBytes := hash.Sum(nil)[:16]
	//Convert the bytes to a string
	return hex.EncodeToString(hashInBytes), nil
}
