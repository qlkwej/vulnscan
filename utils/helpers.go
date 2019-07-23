package utils

import (
	"os"
)


func DefaultPath() string {
	dir, _ := os.Getwd()
	return dir
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func CheckPathIsSrc(binaryPath, sourcePath string) (string, bool) {
	ok, err := PathExists(sourcePath)
	if err != nil {
		panic(err)
	}

	if ok {
		return sourcePath, true
	}

	ok, err = PathExists(binaryPath)
	if err != nil {
		panic(err)
	}

	if ok {
		return binaryPath, false
	}
	panic("Path doesn't PathExists")
	return "", false
}