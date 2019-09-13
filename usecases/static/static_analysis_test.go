package static

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func staticTestAdapter(command entities.Command, entity entities.Entity) error {
	if ent, ok := entity.(*entities.StaticAnalysis); ok {
		command.T.Log(ent)
		assert.NotEmpty(command.T, ent.Files.Files)
		assert.NotEmpty(command.T, ent.Plist.Xml)
		// assert.NotEmpty(command.T, ent.Code.BadDomains)
		assert.NotEmpty(command.T, ent.Binary.Results)
		assert.NotEmpty(command.T, ent.Binary.Libraries)
		if !strings.Contains(command.Path, "Payload") {
			assert.NotEmpty(command.T, ent.Store.Results)
		}
		assert.NotEmpty(command.T, ent.Virus.Report.Scans)
		return nil
	}
	return nil
}

func TestAnalysis(t *testing.T) {
	mainFolder, _ := test.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	paths, err := test.GetTestPaths([]string{"usecases", "static"}, []string{"binary.ipa", "DVIA.ipa", "DVIA-swift.ipa"})
	assert.NoError(t, err)
	for _, p := range paths {
		Analysis(
			entities.Command{
				Path:          p,
				Country:       "us",
				VirusTotalKey: os.Getenv("VIRUS_TOTAL_API_KEY"),
				Source:        false,
				Analysis: map[entities.AnalysisCheck]bool{
					entities.DoBinary: true,
					entities.DoCode:   true,
					entities.DoStore:  true,
					entities.DoFiles:  true,
					entities.DoPList:  true,
				},
				Output: nil,
				T:      t,
			},
			&entities.StaticAnalysis{},
			mocks.GetTestMap(staticTestAdapter),
		)
	}
}
