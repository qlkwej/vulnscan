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
		// Virus Analysis is the only analysis that needs the uncompressed binary. So, we have to store
		// it in a variable, as to the rest of analysis we are going to pass an uncompressed folder
		virusPath = command.Path
	)
	// We change the output so we can print the report ordered later
	command.Output = ioutil.Discard

	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if err := framework.Normalize(command, func(p, sp string) error {
		command.Path = p
		command.SourcePath = sp

		// Plist and store analysis can run in source and binary input
		if command.Analysis[entities.DoPList] || command.Analysis[entities.DoStore] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// As adapter is a struct, asssignment copies.
				var plistAdapter = adapter
				if command.Analysis[entities.DoPList] {
					entity.HasPlist = true
				} else {
					// If user don't want a plist output, user probably don't want plist logs
					plistAdapter.Output.Logger = nil
				}
				plist.Analysis(command, &entity.Plist, plistAdapter)
				if command.Analysis[entities.DoStore] && len(entity.Plist.Id) > 0 {
					command.AppId = entity.Plist.Id
					wg.Add(1)
					go func() {
						defer wg.Done()
						entity.HasStore = true
						store.Analysis(command, &entity.Store, adapter)
					}()
				} else if !command.Analysis[entities.DoStore] {
					_ = adapter.Output.Logger(output.ParseWarning(command, analysisName, "skipping store analysis: not configured"))
				} else if len(entity.Plist.Id) > 0 {
					_ = adapter.Output.Logger(output.ParseWarning(command, analysisName, "skipping store analysis: unable to extract app id from app plist"))
				}
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "skipping plist and store analysis: not configured"))
		}

		// Files analysis can run on source and binary input
		if command.Analysis[entities.DoFiles] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasFiles = true
				files.Analysis(command, &entity.Files, adapter)
			}()
		} else {
			_ = adapter.Output.Logger(output.ParseWarning(command, analysisName, "skipping files analysis"))
		}

		// Code analysis can only be run on source input
		if command.Analysis[entities.DoCode] && len(command.SourcePath) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasCode = true
				code.Analysis(command, &entity.Code, adapter)
			}()
		} else if len(command.SourcePath) == 0 {
			_ = adapter.Output.Logger(output.ParseWarning(
				command, analysisName, "skipping code analysis, only available on source inputs"))
		} else {
			_ = adapter.Output.Logger(output.ParseWarning(
				command, analysisName, "skipping code analysis, not configured"))
		}

		// Binary analysis only runs on binary input
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

		// Virus scan only works on binary input and when the VirusTotal key is set
		if !command.Source && len(command.VirusTotalKey) > 0 && adapter.Services.VirusScan != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entity.HasVirus = true
				virusCommand := command
				virusCommand.Path = virusPath
				_ = adapter.Output.Logger(output.ParseInfo(virusCommand, "Virus Analysis", "starting virus analysis..."))
				if err := adapter.Services.VirusScan(virusCommand, &entity.Virus); err != nil {
						entity.HasVirus = false
					_ = adapter.Output.Error(output.ParseError(virusCommand, "Virus Analysis", err))
					_ = adapter.Output.Logger(output.ParseWarning(command, analysisName,
						fmt.Sprintf("skipping virus analysis, errored with: %s", err)))
						return
				}
				_ = adapter.Output.Logger(output.ParseInfo(virusCommand, "Virus Analysis", "virus analysis completed!"))
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
