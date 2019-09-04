package static

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/usecases/binary"
	"github.com/simplycubed/vulnscan/usecases/code"
	"github.com/simplycubed/vulnscan/usecases/files"
	"github.com/simplycubed/vulnscan/usecases/plist"
	"github.com/simplycubed/vulnscan/usecases/store"
	"io/ioutil"
	"os"
	"sync"
)

func Analysis(command entities.Command, entity *entities.StaticAnalysis, adapter adapters.AdapterMap) {
	output.CheckNil(adapter)
	var (
		wg           sync.WaitGroup
		analysisName = entities.Static
	)
	// We change the output so we can print the report ordered later
	command.Output = ioutil.Discard
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if err := framework.Normalize(command, func(p string) error {
		command.Path = p
		if command.Analysis[entities.DoPList] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasPlist = true
				plist.Analysis(command, &entity.Plist, adapter)
				if command.Analysis[entities.DoStore] {
					command.AppId = entity.Plist.Id
					wg.Add(1)
					go func() {
						defer wg.Done()
						entity.HasStore = true
						store.Analysis(command, &entity.Store, adapter)
					}()
				}
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping plist and store analysis"))
		}
		if command.Analysis[entities.DoFiles] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasFiles = true
				files.Analysis(command, &entity.Files, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping files analysis"))
		}

		if command.Analysis[entities.DoCode] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasCode = true
				code.Analysis(command, &entity.Code, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping code analysis"))
		}

		if !command.Source && command.Analysis[entities.DoBinary] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasBinary = true
				binary.Analysis(command, &entity.Binary, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping binary analysis"))
		}

		if !command.Source && len(command.VirusTotalKey) > 0 && adapter.Services.VirusScan != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasVirus = true
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
	command.Output = os.Stdout
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}
