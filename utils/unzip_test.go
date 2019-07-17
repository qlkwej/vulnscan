package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestWithUnzip(t *testing.T) {
	zipFile, e := FindTest("apps", "source.zip")
	path, e := FindTest("apps", "source")
	if e != nil {
		t.Error(e)
	}
	if err := WithUnzip(zipFile, path, func(p string) error {
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
	}); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Folder was not cleaned")
	}
}

func TestNormalize(t *testing.T) {
	getPath := func(p string) error {
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
	for i, p := range [][]string {
		{"apps", "binary.ipa"},    		// .ipa file
		{"unzip", "iVim.app"},     		// .app file
		{"apps", "binary_zip.zip"},     // .zip file
		{"unzip"},                 		// find the .zip file
	} {
		path, _ := FindTest(p...)
		if e := Normalize(path, false, getPath); e != nil {
			t.Errorf("%d: %s", i, e)
		}
	}
}
