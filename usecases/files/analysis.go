package files

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func Analysis(command utils.Command, entity *entities.FileAnalysis, adapter adapters.AdapterMap) (entities.Entity, error) {
	walkErr := filepath.Walk(command.Path, func(path string, info os.FileInfo, err error) error {
		filePath := path
		dirName, fileName := filepath.Split(path)
		if !strings.HasSuffix(fileName, ".DS_Store") {
			if strings.Contains(fileName, "+") {
				plus2X := filepath.Join(dirName, strings.Replace(fileName, "+", "x", -1))
				err := os.Rename(filePath, plus2X)
				if err != nil {
					return err
				}
				filePath = plus2X
			}
			fileParam := strings.Replace(filePath, command.Path, "", 1)
			entity.Files = append(entity.Files, fileParam)
			ext := filepath.Ext(fileName)
			if r, _ := regexp.MatchString(`cer|pem|cert|crt|pub|key|pfx|p12`, ext); r {
				entity.Certifications = append(entity.Certifications, fileParam)
			}
			if r, _ := regexp.MatchString(`db|sqlitedb|sqlite`, ext); r {
				entity.Databases = append(entity.Databases, fileParam)
			}
			if r, _ := regexp.MatchString(`plist`, ext); r {
				entity.PLists = append(entity.PLists, fileParam)
			}
		}
		return nil
	})
	if walkErr != nil {
		return entity, walkErr
	}
	return entity, nil
}
