package static

import (
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

func Analysis(command utils.Command, entity *entities.StaticAnalysis, adapter adapters.AdapterMap)  {
	var (
		wg sync.WaitGroup
		analysisName = entities.Static
		doVirus = !command.Source && adapter.Services.VirusScan != nil
	)
	// We change the output so we can print the report ordered later
	command.Output = ioutil.Discard
	_ = adapter.Output.Logger(output.ParseInfo(analysisName, "starting"))
	if err := utils.Normalize(command.Path, command.Source, func(p string) error {
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
		}
		if command.Analysis[utils.DoFiles] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				files.Analysis(command, &entity.Files, adapter)
			}()
		}

		if command.Analysis[utils.DoCode] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code.Analysis(command, &entity.Code, adapter)
			}()
		}

		if command.Analysis[utils.DoBinary] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				binary.Analysis(command, &entity.Binary, adapter)
			}()
		}

		if doVirus {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = adapter.Output.Logger(output.ParseInfo(analysisName, "starting virus analysis..."))
				if adapter.Output.Error(output.ParseError(analysisName, adapter.Services.MalwareDomains(command, entity))) != nil {
					return
				}
				_ = adapter.Output.Logger(output.ParseInfo(analysisName, "virus analysis completed!"))
			}()
		}
		wg.Wait()
		return nil
	}); adapter.Output.Error(output.ParseError(analysisName, err)) != nil {
		return
	}
	_ = adapter.Output.Logger(output.ParseInfo(analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(analysisName, err))
	}
}
