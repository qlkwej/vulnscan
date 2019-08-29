package utils

import "os"

// DefaultPath returns the default path
func DefaultPath() string {
	dir, _ := os.Getwd()
	return dir
}

// PathExists checks if the path exists and is accessible
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

// CheckPathIsSrc checks the paths passed by the user and determines if it's a binary or source path
func CheckPathIsSrc(binaryPath, sourcePath string) (string, bool) {
	// If user has not used flags, we check the configuration file
	if binaryPath == "" && sourcePath == "" {
		binaryPath = Configuration.BinaryPath
		sourcePath = Configuration.SourcePath
	}
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
}
