package static

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func staticTestAdapter(command utils.Command, entity entities.Entity) error {
	if ent, ok := entity.(*entities.StaticAnalysis); ok {
		assert.NotEmpty(command.T, ent.Files.Files)
		assert.NotEmpty(command.T, ent.Plist.Xml)
		assert.NotEmpty(command.T, ent.Code.BadDomains)
		assert.NotEmpty(command.T, ent.Binary.Results)
		assert.NotEmpty(command.T, ent.Binary.Libraries)
		assert.NotEmpty(command.T, ent.Store.Results)
		assert.NotEmpty(command.T, ent.Virus.Report.Scans)
		return nil
	}
	return nil
}

func TestAnalysis(t *testing.T) {
	mainFolder, _ := utils.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	testPath, _ := utils.FindTest("apps", "binary.ipa")
	Analysis(
		utils.Command{
			Path:          testPath,
			Country:       "us",
			VirusTotalKey: os.Getenv("VIRUS_TOTAL_API_KEY"),
			Source:        false,
			Analysis: map[utils.AnalysisCheck]bool{
				utils.DoBinary: true,
				utils.DoCode:   true,
				utils.DoStore:  true,
				utils.DoFiles:  true,
				utils.DoPList:  true,
			},
			CheckDomains: true,
			Output:       nil,
			T:            t,
		},
		&entities.StaticAnalysis{},
		mocks.GetTestMap(staticTestAdapter),
	)
}
