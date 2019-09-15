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
	removeFunc := func() {}
	if len(command.Path) > 0 {

		if filepath.Ext(command.Path) == ".zip" || filepath.Ext(command.Path) == ".ipa" {
			// This unzips the content into the temp folder and remove it afterwards.
			tempDir, _ = ioutil.TempDir(filepath.Dir(command.Path), "temp")
			if err = unzipInTemp(command.Path, tempDir); err != nil {
				_ = os.RemoveAll(tempDir)
				return err
			}
			removeFile := tempDir
			removeFunc = func() {
				fmt.Printf("removing %s (%s)\n", removeFile, command.Path)
				_ = os.RemoveAll(removeFile)
			}
			appDir, err := findAppFile(tempDir)
			if err != nil {
				return err
			}
			if appDir != "" {
				tempDir = filepath.Dir(appDir)
			}

		} else if filepath.Ext(command.Path) == ".app" {
			// Create a temp folder
			tempDir, _ = ioutil.TempDir(filepath.Dir(command.Path), "temp")
			_ = os.MkdirAll(tempDir, os.ModePerm)
			_ = os.Chmod(tempDir, 0777)
			// Copy the app to the temp folder
			if e := copy.Copy(command.Path, filepath.Join(tempDir, filepath.Base(command.Path))); e != nil {
				_ = os.RemoveAll(tempDir)
				return fmt.Errorf("error coping files from .app: %s", e)
			}
			removeFunc = func() {
				fmt.Printf("removing %s (%s)\n", tempDir, command.Path)
				_ = os.RemoveAll(tempDir)
			}

		} else if len(filepath.Ext(command.Path)) == 0 {
			// We have a directory, so let's search for a file suspicious of being our app
			appFile, err := findAppFile(command.Path)
			if err != nil {
				return err
			}
			if appFile != "" {
				command.Path = appFile
				return Normalize(command, fn)
			} else {
				return fmt.Errorf("unable to normalize path %s: app not found", command.Path)
			}

		} else {
			return fmt.Errorf("unable to normalize path %s: %s extension not recognized", command.Path, filepath.Ext(command.Path))
		}
	}
	removeSourceFunc := func() {}
	if len(command.SourcePath) > 0 {
		if len(filepath.Ext(command.SourcePath)) == 0 {
			files, err := ioutil.ReadDir(command.SourcePath)
			if err != nil {
				return fmt.Errorf("error reading command.Path (%s) directory: %s", command.SourcePath, err)
			}
			if len(files) > 1 {
				sourceTempDir = command.SourcePath
			} else if len(files) == 1 && (files[0].IsDir() || filepath.Ext(files[0].Name()) == ".zip") {
				command.SourcePath = filepath.Join(command.SourcePath, files[0].Name())
				return Normalize(command, fn)
			}
		} else if filepath.Ext(command.SourcePath) == ".zip" {
			sourceTempDir, _ = ioutil.TempDir(filepath.Dir(command.SourcePath), "source_temp")
			if err = unzipInTemp(command.SourcePath, sourceTempDir); err != nil {
				_ = os.RemoveAll(sourceTempDir)
				return err
			}
			removeFile := sourceTempDir
			files, err := ioutil.ReadDir(sourceTempDir)
			if err != nil {
				return err
			}
			if len(files) == 1 && files[0].Name() == strings.Replace(filepath.Base(command.SourcePath), ".zip", "", 1) {
				sourceTempDir = filepath.Join(sourceTempDir, files[0].Name())
			}
			removeSourceFunc = func() {
				_ = os.RemoveAll(removeFile)
			}
		}
	}

	// Return the function over the tempDir folder and delete it afterwards
	return func(p string, sp string) error {
		defer func() {
			removeFunc()
			removeSourceFunc()
		}()
		return fn(p, sp)
	}(tempDir, sourceTempDir)
}

func findAppFile(p string) (string, error) {
	var appFile string
	if walkErr := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		for _, ext := range []string{".app", ".ipa", ".zip"} {
			if filepath.Ext(path) == ext {
				appFile = path
				// We use EOF error just to mark that we have found the file (to return an error is the only way
				// to exit early from the walk function)
				return io.EOF
			}
		}
		return nil
	}); walkErr != nil && walkErr != io.EOF {
		return "", fmt.Errorf("error walking directory %s to find the .app directory: %s", p, walkErr)
	}
	return appFile, nil
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

func unzipInTemp(filePath, tempPath string) error {
	_ = os.MkdirAll(tempPath, os.ModePerm)

	if err := unzip(filePath, tempPath); err != nil {
		return fmt.Errorf("unzip error: %s", err)
	}
	// Here we have two situations: either we have a subfolder  with the app filePath or we have the app filePath inside a
	// subfolder
	files, err := ioutil.ReadDir(tempPath)
	if err != nil {
		return fmt.Errorf("error reading directory %s: %s", tempPath, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("extraction failed: the folder is empty")
	}

	return nil
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
