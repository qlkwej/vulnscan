package binary

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"path"
	"strings"
)

func GetTypeInfo(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	entity.BinType = entities.ObjC
	for _, lib := range entity.Libraries {
		if strings.Contains(lib, "libswiftCore.dylib") {
			entity.BinType = entities.Swift
			break
		}
	}
	return entity, nil
}

func OtoolInfo(command utils.Command, entity *entities.BinaryAnalysis, adapters ...adapters.Adapter) (entities.Entity, error) {
	for _, adapter := range adapters {
		if _, err := adapter(command, entity); err != nil {
			return nil, err
		}
	}
	return entity, nil
}

func Analysis(command utils.Command, entity *entities.BinaryAnalysis, adapters ...adapters.Adapter) (entities.Entity, error) {
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
		if _, err := GetMachoInfo(utils.Command{Path:binPath}, entity); err != nil {
			return err
		}
		_, _ = GetTypeInfo(command, entity)
		if _, err := OtoolInfo(utils.Command{Path:binPath}, entity, adapters...); err !=  nil {
			return err
		}
		return nil
	}); e != nil {
		return nil, e
	}
	return entity, nil
}
