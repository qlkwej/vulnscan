package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/otiai10/copy"
)

func unzip(src, dest string) error {
	_ = os.Chmod(dest, 0777)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

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

func WithUnzip(zipFile, path string, fn func(p string) error) error {
	_ = os.MkdirAll(path, os.ModePerm)
	defer os.RemoveAll(path)
	err := unzip(zipFile, path)
	if err != nil {
		return fmt.Errorf("unzip error: %s", err)
	}
	// Here we have two situations: either we have a subfolder  with the app file or we have the app file inside a
	// subfolder
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return fmt.Errorf("error reading directory %s: %s", path, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("extraction failed: the folder is empty")
	}
	if len(files) > 1 || filepath.Ext(files[0].Name()) == ".app" {
		return fn(path)
	}
	// We have to run the function into the uncompressed folder in temp, that is named as the zipFile
	return fn(filepath.Join(path, files[0].Name()))
}


// Tries to adapt the input folder to different cases, so all the analysis can start from a common
// folder structure, independently of how the user has passed the address to scan.
// It follows these rules:
//
//		If isSrc flag is true, the folder is treated as the main folder without further analysis.
//
//		If the file extension is zip of ipa, the folder is uncompressed into a temporary one, that
//		will be later be deleted. It's expected that this folder contains a .app folder as the content.
//
//		If the file extension is app, the file is moved to another temporary empty folder where the analysis
// 		is performed. This is because we don't know if the user may have other app folders in the same route
//		and we wan't to treat the route as in the case where an ipa or zip is passed to the app.
//
//		If the file is a directory, we look for an app, ipa or zip file and call Normalize again with it.
func Normalize(path string, isSrc bool, fn func(p string)error) error {
	if isSrc {
		return fn(path)  // And don't look back
	} else if filepath.Ext(path) == ".zip" || filepath.Ext(path) == ".ipa" {
		// This unzips the content into the temp folder and remove it afterwards.
		tempDir := filepath.Join(filepath.Dir(path), "temp")
		return WithUnzip(path, tempDir, fn)
	} else if filepath.Ext(path) == ".app" {
		// Create a temp folder
		tempDir := filepath.Join(filepath.Dir(path), "temp")
		_ = os.MkdirAll(tempDir, os.ModePerm)
		_ = os.Chmod(tempDir, 0777)
		// Copy the app to the temp folder
		if e := copy.Copy(path, filepath.Join(tempDir, filepath.Base(path))); e != nil {
			return e
		}
		// Return the function over the tempDir folder and delete it afterwards
		return func(p string) error {
			defer os.RemoveAll(p)
			return fn(p)
		}(tempDir)

	} else if len(filepath.Ext(path)) == 0 {
		// We have a directory, so let's search for a file suspicious of being our app
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}
		var appObj string
		for _, f := range files {
			for _, suffix := range []string{".app", ".ipa", ".zip"} {
				if strings.HasSuffix(f.Name(), suffix) {
					appObj = f.Name()
					break
				}
			}

		}
		if appObj != "" {
			return Normalize(filepath.Join(path, appObj), false, fn)
		}
	}
	return fmt.Errorf("unable to normalize path %s", path)
}

func GetApp(path string) (app string, err error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return app, err
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".app" {
			return path + string(os.PathSeparator) + f.Name(), nil
		}
	}
	return app, fmt.Errorf(".app file not found in parent folder")
}
