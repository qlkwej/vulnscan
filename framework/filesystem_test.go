package framework

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	var extractFilenames = func(path string) []string {
		files, err := ioutil.ReadDir(path)
		var fileNames []string
		assert.NoError(t, err)
		for _, f := range files {
			if !strings.HasPrefix(f.Name(), ".") {
				fileNames = append(fileNames, f.Name())
			}
		}
		return fileNames
	}
	var checkFunc = func(p, sp string) error {

		if len(p) > 0 {
			fileNames := extractFilenames(p)
			t.Logf("files: %s\n", fileNames)
			assert.Len(t, fileNames, 1)
			assert.Equal(t, "appName.app", fileNames[0])
		} else {
			fileNames := extractFilenames(sp)
			t.Logf("files: %s\n", fileNames)
			assert.Len(t, fileNames, 2)
			fileSet := map[string]bool{}
			for _, f := range fileNames {
				fileSet[f] = true
			}
			assert.True(t, fileSet["sourceName"])
			assert.True(t, fileSet["sourceName.xcodeproj"])
		}
		return nil
	}
	for k, v := range map[[3]string]bool{
		{"framework", "filesystem", "binary"}:     true,
		{"framework", "filesystem", "binary.app"}: true,
		{"framework", "filesystem", "binary.zip"}: true,
		{"framework", "filesystem", "binary.ipa"}: true,
		{"framework", "filesystem", "source"}:     false,
		{"framework", "filesystem", "source.zip"}: false,
	} {
		path, _ := test.FindTest(k[:]...)
		if v {
			_ = Normalize(entities.Command{Path: path}, checkFunc)
		} else {
			_ = Normalize(entities.Command{SourcePath: path}, checkFunc)
		}
	}
}

func TestExtractBinPath(t *testing.T) {
	path, _ := test.FindTest("framework", "filesystem", "binary", "something")
	command := entities.Command{Path: path}
	assert.NoError(t, ExtractBinPath(&command))
	assert.Equal(t, filepath.Join(path, "appName.app", "appName"), command.Path)
	assert.Equal(t, "appName", command.AppName)
}
