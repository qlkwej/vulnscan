package binary

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters/output"
	"os"
	"path"
	"strings"

	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)


func Analysis(command utils.Command, entity *entities.BinaryAnalysis, adapter adapters.AdapterMap) {
	var analysisName = entities.Binary
	_ = adapter.Output.Logger(output.ParseInfo(analysisName, "starting"))
	if e := utils.Normalize(command.Path, false, func(p string) error {

		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		_ = adapter.Output.Logger(output.ParseInfo(analysisName, fmt.Sprintf("application found on route %s", appPath)))

		if len(command.AppName) == 0 {
			command.AppName = strings.Replace(path.Base(appPath), path.Ext(appPath), "", 1)
		}
		binPath := path.Join(appPath, command.AppName)

		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			return fmt.Errorf("unable to find the binary at %s", binPath)
		}
		_ = adapter.Output.Logger(output.ParseInfo(analysisName, "performing macho information extraction"))
		if err := GetMachoInfo(utils.Command{Path:binPath}, entity); err != nil {
			return err
		}
		_ = adapter.Output.Logger(output.ParseInfo(analysisName, "macho information extraction completed"))
		getTypeInfo(command, entity)
		if err := otoolInfo(utils.Command{Path: binPath}, entity, adapter); err !=  nil {
			return err
		}
		return nil
	}); e != nil {
		if adapter.Output.Error(output.ParseError(analysisName, e)) != nil {
			return
		}
	}
	_ = adapter.Output.Logger(output.ParseInfo(analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(analysisName, err))
	}
}

// Extracts the information about the language used by the application: objective c or swift. If libswiftcore.dylib
// is detected, the application is categorized as swift, so mixed language applications would be marked as swift
// applications
// TODO: imrpove the command to detect mixed language applications ?
func getTypeInfo(command utils.Command, entity *entities.BinaryAnalysis) {
	entity.BinType = entities.ObjC
	for _, lib := range entity.Libraries {
		if strings.Contains(lib, "libswiftCore.dylib") {
			entity.BinType = entities.Swift
			break
		}
	}
}

func otoolInfo(command utils.Command, entity *entities.BinaryAnalysis, adapter adapters.AdapterMap) error {
	var analysisName = entities.Binary
	for n, a := range map[string]adapters.Adapter{
		"headers": adapter.Tools.Headers,
		"libraries": adapter.Tools.Libs,
		"symbols": adapter.Tools.Symbols,
		"class dump": adapter.Tools.ClassDump,
	} {
		if a != nil {
			_ = adapter.Output.Logger(output.ParseInfo(analysisName, fmt.Sprintf("performing %s information extraction", n)))
			if err := a(command, entity); err != nil {
				return err
			}
			_ = adapter.Output.Logger(output.ParseInfo(analysisName, fmt.Sprintf("%s information extraction completed", n)))
		}
	}
	return nil
}

