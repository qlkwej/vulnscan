package static

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/usecases/binary"
	"github.com/simplycubed/vulnscan/usecases/code"
	"github.com/simplycubed/vulnscan/usecases/files"
	"github.com/simplycubed/vulnscan/usecases/plist"
	"github.com/simplycubed/vulnscan/usecases/store"
	"github.com/simplycubed/vulnscan/utils"
	"io/ioutil"
	"sync"
)

func Analysis(command utils.Command, entity *entities.StaticAnalysis, adapter adapters.AdapterMap) {
	output.CheckNil(adapter)
	var (
		wg           sync.WaitGroup
		analysisName = entities.Static
	)
	// We change the output so we can print the report ordered later
	command.Output = ioutil.Discard
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if err := utils.Normalize(command.Path, command.Source, func(p string) error {
		command.Path = p
		if command.Analysis[utils.DoPList] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				plist.Analysis(command, &entity.Plist, adapter)
				if command.Analysis[utils.DoStore] {
					command.AppId = entity.Plist.Id
					wg.Add(1)
					go func() {
						defer wg.Done()
						store.Analysis(command, &entity.Store, adapter)
					}()
				}
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping plist and store analysis"))
		}
		if command.Analysis[utils.DoFiles] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				files.Analysis(command, &entity.Files, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping files analysis"))
		}

		if command.Analysis[utils.DoCode] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code.Analysis(command, &entity.Code, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping code analysis"))
		}

		if !command.Source && command.Analysis[utils.DoBinary] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				binary.Analysis(command, &entity.Binary, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping binary analysis"))
		}

		if !command.Source && len(command.VirusTotalKey) > 0 && adapter.Services.VirusScan != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting virus analysis..."))
				if adapter.Output.Error(output.ParseError(command, analysisName, adapter.Services.VirusScan(command, &entity.Virus))) != nil {
					return
				}
				_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "virus analysis completed!"))
			}()
		} else {
			var reason string
			if command.Source {
				reason = "cannot run on source files"
			} else if len(command.VirusTotalKey) == 0 {
				reason = "total virus API key not found"
			} else if adapter.Services.VirusScan == nil {
				reason = "virus scan adapter not loaded, review your configuration"
			}
			_ = adapter.Output.Logger(output.ParseWarning(command, analysisName,
				fmt.Sprintf("skipping virus analysis: %s", reason)))
		}
		wg.Wait()
		return nil
	}); adapter.Output.Error(output.ParseError(command, analysisName, err)) != nil {
		return
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}
