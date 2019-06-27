package ios

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func unzip(src, dest string) error {
	_ = os.Chmod(dest, 0777)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	// Use the dest as direct parent
	dest = filepath.Dir(dest)

	for _, f := range r.File {

		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			// Make Folder
			_ = os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		_ = outFile.Close()
		_ = rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func withUnzip(zipFile, path string, fn func()) error {
	_ = os.MkdirAll(path, os.ModePerm)
	defer os.RemoveAll(path)
	err := unzip(zipFile, path)
	if err != nil {
		return err
	}
	fn()
	return nil
}

func TestPlistSourceSearch(t *testing.T) {
	zipFile, _ := filepath.Abs("../test_files/plist/source.zip")
	path, _ := filepath.Abs("../test_files/plist/source")
	if err:= withUnzip(zipFile, path, func() {
		if file, name, err := findPListFile(path, true); err != nil || len(file) == 0 {
			t.Errorf("Failed to find plist file in source with error %s", err)
		} else if len(name) == 0 {
			t.Errorf("Failed to extract name from source")
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPListBinarySearch(t *testing.T) {
	zipFile, _ := filepath.Abs("../test_files/plist/binary.zip")
	path, _ := filepath.Abs("../test_files/plist/binary")
	if err:=withUnzip(zipFile, path, func() {
		if file, name, err := findPListFile(path, false); err != nil || len(file) == 0 {
			t.Errorf("Failed to find plist file in source with error %s", err)
		} else if len(name) == 0 {
			t.Errorf("Failed to extract name from source")
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestMultiplePListAnalysis(t *testing.T) {
	for i := 1; i <= 5; i++ {
		path, _ := filepath.Abs(fmt.Sprintf("../test_files/plist/plistfiles/plist%d.plist", i))
		if _, err := makePListAnalysis(path, fmt.Sprintf("App%d", i), true); err != nil {
			t.Errorf("Failed to extract plist data from %s with error %s", path, err)
		}
	}
}

func TestPlistSourceAnalysis(t *testing.T) {
	zipFile, _ := filepath.Abs("../test_files/plist/source.zip")
	path, _ := filepath.Abs("../test_files/plist/source")
	if err:=withUnzip(zipFile, path, func() {
		if result, err := PListAnalysis(path, true); err != nil || len(result.PListXML) == 0 {
			t.Errorf("Plist source analysis failed with error %s", err)
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPListBinaryAnalysis(t *testing.T) {
	zipFile, _ := filepath.Abs("../test_files/plist/binary.zip")
	path, _ := filepath.Abs("../test_files/plist/binary")
	if err:=withUnzip(zipFile, path, func() {
		if result, err := PListAnalysis(path, false); err != nil || len(result.PListXML) == 0 {
			t.Errorf("Plist source analysis failed with error %s", err)
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}