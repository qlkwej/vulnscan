package framework

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/otiai10/copy"
	"github.com/simplycubed/vulnscan/entities"
)

// Normalize tries to adapt the input folder to different cases, so all the analysis can start from a common
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
func Normalize(command entities.Command, fn func(p string, sp string) error) (err error) {
	var tempDir, sourceTempDir string
	if len(command.Path) > 0 {
		if filepath.Ext(command.Path) == ".zip" || filepath.Ext(command.Path) == ".ipa" {
			// This unzips the content into the temp folder and remove it afterwards.
			tempDir = filepath.Join(filepath.Dir(command.Path), "temp")
			tempDir, err = unzipInTemp(command.Path, tempDir)
			if err != nil {
				_ = os.RemoveAll(tempDir)
				return err
			}

		} else if filepath.Ext(command.Path) == ".app" {
			// Create a temp folder
			tempDir = filepath.Join(filepath.Dir(command.Path), "temp")
			_ = os.MkdirAll(tempDir, os.ModePerm)
			_ = os.Chmod(tempDir, 0777)
			// Copy the app to the temp folder
			if e := copy.Copy(command.Path, filepath.Join(tempDir, filepath.Base(command.Path))); e != nil {
				_ = os.RemoveAll(tempDir)
				return fmt.Errorf("error coping files from .app: %s\n", e)
			}


		} else if len(filepath.Ext(command.Path)) == 0 {
			// We have a directory, so let's search for a file suspicious of being our app
			files, err := ioutil.ReadDir(command.Path)
			if err != nil {
				return fmt.Errorf("error reading command.Path (%s) directory: %s", command.Path, err)
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
				command.Path = filepath.Join(command.Path, appObj)
				return Normalize(command, fn)
			}

		} else {
			return fmt.Errorf("unable to normalize path %s", command.Path)
		}
	}

	if len(command.SourcePath) > 0 {
		if len(filepath.Ext(command.SourcePath)) == 0 {
			files, err := ioutil.ReadDir(command.SourcePath)
			if err != nil {
				return fmt.Errorf("error reading command.Path (%s) directory: %s", command.SourcePath, err)
			}
			if len(files) > 1 {
				sourceTempDir = command.SourcePath
			} else if len(files) == 1 && files[0].IsDir() || filepath.Ext(files[0].Name()) == ".zip" {
				command.SourcePath = filepath.Join(command.SourcePath, files[0].Name())
				return Normalize(command, fn)
			}
		} else if filepath.Ext(command.SourcePath) == ".zip" {
			sourceTempDir = filepath.Join(filepath.Dir(command.SourcePath), "temp")
			sourceTempDir, err = unzipInTemp(command.SourcePath, sourceTempDir)
			if err != nil {
				_ = os.RemoveAll(sourceTempDir)
				return err
			}
		}
	}

	// Return the function over the tempDir folder and delete it afterwards
	return func(p string, sp string) error {
		defer func() {
			_ = os.RemoveAll(p)
			_ = os.RemoveAll(sp)
		}()
		return fn(p, sp)
	}(tempDir, sourceTempDir)
}

func ExtractBinPath(command *entities.Command) error {
	var (
		files, err = ioutil.ReadDir(command.Path)
		found      = false
	)

	if err != nil {
		return fmt.Errorf("read %s directory failed: %s", command.Path, err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".app" {
			command.Path = filepath.Join(command.Path, f.Name())
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf(".app file not found in parent folder %s", command.Path)
	}
	if len(command.AppName) == 0 {
		command.AppName = strings.Replace(path.Base(command.Path), path.Ext(command.Path), "", 1)
	}
	command.Path = path.Join(command.Path, command.AppName)
	return nil
}

func unzipInTemp(filePath, tempPath string) (tp string, err error) {
	_ = os.MkdirAll(tempPath, os.ModePerm)

	if err = unzip(filePath, tempPath); err != nil {
		return tp, fmt.Errorf("unzip error: %s", err)
	}
	// Here we have two situations: either we have a subfolder  with the app filePath or we have the app filePath inside a
	// subfolder
	files, err := ioutil.ReadDir(tempPath)
	if err != nil {
		return tp, fmt.Errorf("error reading directory %s: %s", tempPath, err)
	}
	if len(files) == 0 {
		return tp, fmt.Errorf("extraction failed: the folder is empty")
	}
	if len(files) > 1 || filepath.Ext(files[0].Name()) == ".app" {
		return tempPath, nil
	}
	// We have to run the function into the uncompressed folder in temp, that is named as the filePath
	return filepath.Join(tempPath, files[0].Name()), nil
}

// withUnzip extracts file
func withUnzip(zipFile, path string, fn func(p string) error) error {
	_ = os.MkdirAll(path, os.ModePerm)
	defer func() {
		_ = os.RemoveAll(path)
	}()
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

func unzip(src, dest string) error {
	_ = os.Chmod(dest, 0777)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		_ = r.Close()
	}()

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
