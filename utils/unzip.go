package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
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

func WithUnzip(zipFile, path string, fn func()) error {
	_ = os.MkdirAll(path, os.ModePerm)
	defer os.RemoveAll(path)
	err := unzip(zipFile, path)
	if err != nil {
		return err
	}
	fn()
	return nil
}
