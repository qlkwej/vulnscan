package utils

import (
	"log"
	"os"
	"runtime"
)

func EOL() string {
	if runtime.GOOS == "windows" {
		return "\r\n"
	} else {
		return "\n"
	}
}
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
		log.Fatal(err)
	}

	if ok {
		log.Printf("Source Path: %s", sourcePath)
		return sourcePath, true
	}

	ok, err = PathExists(binaryPath)
	if err != nil {
		log.Fatal(err)
	}

	if ok {
		log.Printf("Binary Path: %s", binaryPath)
		return binaryPath, false
	}
	log.Fatal("Path doesn't PathExists")
	return "", false
}