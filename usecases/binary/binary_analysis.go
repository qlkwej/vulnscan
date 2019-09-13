package binary

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters/output"
	"os"
	"strings"

	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
)

// BinaryAnalysis works only on binary inputs.
func Analysis(command entities.Command, entity *entities.BinaryAnalysis, adapter adapters.AdapterMap) {
	output.CheckNil(adapter)
	var analysisName = entities.Binary
	if command.Source {
		_ = adapter.Output.Error(output.ParseError(command, analysisName,
			fmt.Errorf("binary analysis can only be run on binary input")))
		return
	}

	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if e := framework.Normalize(command, func(p, sp string) error {
		command.Path = p
		if err := framework.ExtractBinPath(&command); err != nil {
			return err
		}
		if _, err := os.Stat(command.Path); os.IsNotExist(err) {
			return fmt.Errorf("unable to find the binary at %s", command.Path)
		}
		_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "application binary found on route %s", command.Path))
		_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "performing macho information extraction"))
		if err := GetMachoInfo(command, entity); err != nil {
			return err
		}
		_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "macho information extraction completed"))
		getTypeInfo(command, entity)
		if err := otoolInfo(command, entity, adapter); err != nil {
			return err
		}
		return nil
	}); e != nil {
		if adapter.Output.Error(output.ParseError(command, analysisName, e)) != nil {
			return
		}
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}

// Extracts the information about the language used by the application: objective c or swift. If libswiftcore.dylib
// is detected, the application is categorized as swift, so mixed language applications would be marked as swift
// applications
// TODO: imrpove the command to detect mixed language applications ?
func getTypeInfo(command entities.Command, entity *entities.BinaryAnalysis) {
	entity.BinType = entities.ObjC
	for _, lib := range entity.Libraries {
		if strings.Contains(lib, "libswiftCore.dylib") {
			entity.BinType = entities.Swift
			break
		}
	}
}

func otoolInfo(command entities.Command, entity *entities.BinaryAnalysis, adapter adapters.AdapterMap) error {
	output.CheckNil(adapter)
	var analysisName = entities.Binary
	for n, a := range map[string]adapters.ToolAdapter{
		"headers":    adapter.Tools.Headers,
		"libraries":  adapter.Tools.Libs,
		"symbols":    adapter.Tools.Symbols,
		"class dump": adapter.Tools.ClassDump,
	} {
		if a != nil {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "performing %s information extraction", n))
			if err := a(command, entity); err != nil {
				return err
			}
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, fmt.Sprintf("%s information extraction completed", n)))
		}
	}
	return nil
}
