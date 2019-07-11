package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var (
	wd, _ = os.Getwd()
)

func Expect(t *testing.T, a interface{}, b interface{}) {
	_, fn, line, _ := runtime.Caller(1)
	fn = strings.Replace(fn, wd+"/", "", -1)

	if !reflect.DeepEqual(a, b) {
		t.Errorf("(%s:%d) Expected %v (type %v) - Got %v (type %v)", fn, line, b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

// Utility function to help find the test_files folder in different test environments. This solves
// the problem where running tests from an IDE and from command line differed in how the test_files
// folder was determined to be.
//
// The function first looks for an environment variable with the project path. If it doesn't exist, it tries
// to guess it looking for the vulnscan folder in the current absolute path.
func FindTest(testFilePath ...string) (string, error) {
	var sb strings.Builder
	if envPath := os.Getenv("TEST_WORKING_DIRECTORY"); len(envPath) > 0 {
		sb.WriteString(envPath)
		if !strings.HasPrefix(envPath, string(os.PathSeparator)) {
			sb.WriteString(string(os.PathSeparator))
		}
		sb.WriteString("test_files")
		for _, s := range testFilePath {
			sb.WriteString(string(os.PathSeparator))
			sb.WriteString(s)
		}
		return sb.String(), nil
	}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	absPath, _ := filepath.Abs(dir)
	pathList := strings.Split(absPath, string(os.PathSeparator))
	// We search for the last "vulnscan" in the current path, that should be the project main folder.
	if pos := func (s []string) int {
		last := -1
		for p, v := range s {
			if v == "vulnscan" {
				last = p
			}
		}
		return last
	}(pathList); pos != len(pathList) - 1 {
		if pos == -1 {
			// If we don't find the
			return "", fmt.Errorf("vulnscan main directory not found")
		}
		// If we are not in the vulnscan folder, we remove all the children from the pathList
		pathList = pathList[:pos + 1]
	}
	sb.WriteString(strings.Join(pathList, string(os.PathSeparator)) + string(os.PathSeparator))
	sb.WriteString("test_files")
	for _, s := range testFilePath {
		sb.WriteString(string(os.PathSeparator))
		sb.WriteString(s)
	}
	return sb.String(), nil
}
