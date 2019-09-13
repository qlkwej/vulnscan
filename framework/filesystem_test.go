package framework

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestWithUnzip(t *testing.T) {
	zipFile, e := test.FindTest("framework", "filesystem", "unzip", "source.zip")
	assert.NoError(t, e)
	path, e := test.FindTest("framework", "filesystem", "unzip", "source")
	assert.NoError(t, e)
	assert.NoError(t, withUnzip(zipFile, path, func(p string) error {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return fmt.Errorf("folder %s was not created", p)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Readdirnames(1) // Or f.Readdir(1)
		if err == io.EOF {
			return fmt.Errorf("created folder at %s is empty", p)
		}
		return nil
	}))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Folder was not cleaned")
	}
}

func TestNormalize(t *testing.T) {
	f, e := test.FindTest("framework", "filesystem", "iVim.app")
	assert.NoError(t, e)
	assert.NoError(t, os.MkdirAll(f, os.ModePerm))
	getPath := func(p, sp string) error {
		if _, err := os.Stat(filepath.Join(p, "iVim.app")); os.IsNotExist(err) {
			files, e := ioutil.ReadDir(p)
			if e != nil {
				return e
			}
			var fNames []string
			for _, f := range files {
				fNames = append(fNames, f.Name())
			}
			return fmt.Errorf("app not found in folder %s, files found: %d - [%v]", p, len(files), fNames)
		}
		return nil
	}
	for i, p := range [][]string{
		{"framework", "filesystem", "binary.ipa"},     // .ipa file
		{"framework", "filesystem", "iVim.app"},       // .app file
		{"framework", "filesystem", "binary_zip.zip"}, // .zip file
		{"framework", "filesystem"},                   // find the .zip file
	} {
		path, _ := test.FindTest(p...)
		if e := Normalize(entities.Command{Path: path, Source: false}, getPath); e != nil {
			t.Errorf("%d: %s", i, e)
		}
	}
}


func TestExtractBinPath(t *testing.T) {
	path, _ := test.FindTest("framework", "filesystem")
	command := entities.Command{Path: path}
	assert.NoError(t, ExtractBinPath(&command))
	assert.Equal(t, filepath.Join(path, "iVim.app", "iVim"), command.Path)
	assert.Equal(t, "iVim", command.AppName)
}

