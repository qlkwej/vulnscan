package binary

import (
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func binaryTestAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	assert.Len(command.T, entity.Results, 13)
	assert.Len(command.T, entity.Libraries, 25)
	assert.Equal(command.T, entities.Swift, entity.BinType)
	assert.Equal(command.T, entities.Bits64, entity.Macho.Bits)
	assert.Equal(command.T, entities.LittleEndian, entity.Macho.Endianness)
	assert.Equal(command.T, entities.X8664, entity.Macho.Cpu)
	return nil
}

func TestAnalysis(t *testing.T) {
	ipaPath, _ := utils.FindTest("apps", "binary.ipa")
	var (
		command = utils.Command{
			Path: ipaPath,
			T:    t,
		}
		entity = entities.BinaryAnalysis{}
		adapter = adapters.AdapterMap{
			Tools:    adapters.ToolAdapters{
				ClassDump: mocks.MockClassDumpAdapter,
				Libs:      mocks.LibsAdapter,
				Headers:   mocks.HeadersAdapter,
				Symbols:   mocks.SymbolsAdapter,
			},
			Output:   adapters.OutputAdapters{
				Logger: nil,
				Result: nil,
				Error:  nil,
			},
		}
	)

}
