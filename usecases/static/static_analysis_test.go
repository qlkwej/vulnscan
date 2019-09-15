package static

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func binaryIpaTestAdapter(command entities.Command, entity entities.Entity) error {
	if ent, ok := entity.(*entities.StaticAnalysis); ok {
		assert.NotEmpty(command.T, ent.Files.Files)
		assert.NotEmpty(command.T, ent.Plist.Xml)
		assert.NotEmpty(command.T, ent.Binary.Results)
		assert.NotEmpty(command.T, ent.Binary.Libraries)
		assert.NotEmpty(command.T, ent.Store.Results)
		assert.NotEmpty(command.T, ent.Virus.Report.Scans)
		return nil
	}
	return nil
}

func dviaTestAdapter(command entities.Command, entity entities.Entity) error {
	if ent, ok := entity.(*entities.StaticAnalysis); ok {
		assert.NotEmpty(command.T, ent.Files.Files)
		assert.NotEmpty(command.T, ent.Plist.Xml)
		assert.NotEmpty(command.T, ent.Binary.Results)
		assert.NotEmpty(command.T, ent.Binary.Libraries)
		assert.NotEmpty(command.T, ent.Virus.Report.Scans)
		return nil
	}
	return nil
}

func doubleDviaTestAdapter(command entities.Command, entity entities.Entity) error {
	if ent, ok := entity.(*entities.StaticAnalysis); ok {
		assert.NotEmpty(command.T, ent.Files.Files)
		assert.NotEmpty(command.T, ent.Plist.Xml)
		assert.NotEmpty(command.T, ent.Binary.Results)
		assert.NotEmpty(command.T, ent.Binary.Libraries)
		assert.NotEmpty(command.T, ent.Code.Codes)
		assert.NotEmpty(command.T, ent.Code.Apis)
		assert.NotEmpty(command.T, ent.Virus.Report.Scans)
		return nil
	}
	return nil
}

func TestAnalysis(t *testing.T) {
	mainFolder, _ := test.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	var testMap = map[string]func(command entities.Command, entity entities.Entity) error{}
	for k, v := range map[string]func(command entities.Command, entity entities.Entity) error{
		"binary.ipa":        binaryIpaTestAdapter,
		"DVIA.ipa":          dviaTestAdapter,
		"DVIA-v2-swift.ipa": dviaTestAdapter,
	} {
		tf, err := test.FindTest("usecases", "static")
		assert.NoError(t, err)
		tf = filepath.Join(tf, k)
		testMap[tf] = v
	}
	for k, v := range testMap {
		Analysis(
			entities.Command{
				Path:          k,
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
			mocks.GetTestMap(v),
		)
	}
}

func TestDoubleAnalysis(t *testing.T) {
	mainFolder, _ := test.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	var testMap = map[[2]string]func(command entities.Command, entity entities.Entity) error{}
	for k, v := range map[string]func(command entities.Command, entity entities.Entity) error{
		"DVIA.ipa|DVIA.zip":             doubleDviaTestAdapter,
		"DVIA-v2-swift.ipa|DVIA-v2.zip": doubleDviaTestAdapter,
	} {
		tf, err := test.FindTest("usecases", "static")
		assert.NoError(t, err)
		names := strings.Split(k, "|")
		binary := names[0]
		source := names[1]
		btf := filepath.Join(tf, binary)
		stf := filepath.Join(tf, source)
		testMap[[...]string{btf, stf}] = v
	}
	for k, v := range testMap {
		Analysis(
			entities.Command{
				Path:          k[0],
				SourcePath:    k[1],
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
			mocks.GetTestMap(v),
		)
	}
}
