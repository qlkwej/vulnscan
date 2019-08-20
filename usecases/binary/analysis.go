package binary

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"path"
	"strings"
)




func Analysis(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	if e := utils.Normalize(command.Path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		if len(command.AppName) == 0 {
			command.AppName = strings.Replace(path.Base(appPath), path.Ext(appPath), "", 1)
		}
		binPath := path.Join(appPath, command.AppName)
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			return fmt.Errorf("unable to find the binary at %s", binPath)
		}
		if _, err := GetMachoInfo(utils.Command{Path:binPath}, &entity.Macho); err != nil {
			return err
		}

		return nil
	}); e != nil {
		return nil, e
	}
	return nil, nil
}
