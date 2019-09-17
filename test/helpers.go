package test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FindMainFolder finds the main project folder
func FindMainFolder() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	absPath, _ := filepath.Abs(dir)
	pathList := strings.Split(absPath, string(os.PathSeparator))
	// We search for the last "vulnscan" in the current path, that should be the project main folder.
	if pos := func(s []string) int {
		last := -1
		for p, v := range s {
			if v == "vulnscan" {
				last = p
			}
		}
		return last
	}(pathList); pos != len(pathList)-1 {
		if pos == -1 {
			// If we don't find the
			return "", fmt.Errorf("vulnscan main directory not found")
		}
		// If we are not in the vulnscan folder, we remove all the children from the pathList
		pathList = pathList[:pos+1]
	}
	return string(os.PathSeparator) + filepath.Join(pathList...), nil
}

// FindTest is a utility function to help find the test_files folder in different test environments. This solves
// the problem where running tests from an IDE and from command line differed in how the test_files
// folder was determined to be.
//
// The function first looks for an environment variable with the project path. If it doesn't exist, it tries
// to guess it looking for the vulnscan folder in the current absolute path.
func FindTest(testFilePath ...string) (tf string, err error) {
	var mainFolder string
	if envPath := os.Getenv("TEST_WORKING_DIRECTORY"); len(envPath) > 0 {
		mainFolder = envPath
	} else {
		mainFolder, err = FindMainFolder()
		if err != nil {
			return "", err
		}
	}
	route := append([]string{mainFolder, "test", "data"}, testFilePath...)
	return filepath.Join(route...), nil
}

func FindTools() (string, error) {
	main, err := FindMainFolder()
	if err != nil {
		return "", nil
	}
	return filepath.Join(main, "test", "tools"), nil
}

func GetTestPaths(baseRoute []string, fileNames []string) ([]string, error) {
	var paths []string
	main, err := FindMainFolder()
	if err != nil {
		return paths, err
	}
	baseRoute = append([]string{main, "test", "data"}, baseRoute...)
	for _, f := range fileNames {
		route := append(baseRoute, f)
		paths = append(paths, filepath.Join(route...))
	}
	return paths, nil
}

// WithPipeStdout writes to standard out
func WithPipeStdout(printerFunc func() error) (string, error) {
	// Let's hack the stdout to get the help message captured
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Use a goroutine so printing can't block indefinitely
	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// Generate the help message
	if e := printerFunc(); e != nil {
		return "", e
	}

	// Collect the results (the regex is needed to remove some noise generated by the context)
	_ = w.Close()
	os.Stdout = old

	return <-outC, nil
}
