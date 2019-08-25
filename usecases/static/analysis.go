package static

import (
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/usecases/plist"
	"github.com/simplycubed/vulnscan/utils"
)

func Analysis(command utils.Command, entity *entities.StaticAnalysis, adapter adapters.AdapterMap) (entities.Entity, error) {
	type analysisError map[string]interface{}
	var nStreams int
	for _, v := range command.Analysis {
		if v {
			nStreams += 1
		}
	}
	if !command.Source && adapter.Services.VirusScan != nil {
		nStreams += 1
	}
	if err := utils.Normalize(command.Path, command.Source, func(p string) error {
		if command.Analysis[utils.DoPList] {
			go func() {
				_, err := plist.Analysis(command, &entity.Plist)
			}()
		}
		if command.Analysis[utils.DoFiles] {
			go func() {

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
