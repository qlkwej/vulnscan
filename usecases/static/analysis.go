package static

import (
	"bufio"
	"bytes"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/usecases/plist"
	"github.com/simplycubed/vulnscan/utils"
	"sync"
)

func Analysis(command utils.Command, entity *entities.StaticAnalysis, adapter adapters.AdapterMap) (entities.Entity, error) {
	var (
		wg sync.WaitGroup
		buffer bytes.Buffer
		writer = bufio.NewWriter(&buffer)
		doVirus = !command.Source && adapter.Services.VirusScan != nil
	)
	// We change the output so we can collect the messages to a buffer and print all the report at once
	command.Output = writer

	if err := utils.Normalize(command.Path, command.Source, func(p string) error {
		if command.Analysis[utils.DoPList] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = plist.Analysis(command, &entity.Plist)
			}()
		}
		if command.Analysis[utils.DoFiles] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = files.Analysis(command, &entity.Plist)
			}()
		}
		if !command.Source && adapter.Services.VirusScan != nil {
			go func() {

			}()
		}
		return nil
	}); err != nil {
		return entity, err
	}
}
