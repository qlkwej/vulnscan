package binary

import (
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func binaryTestAdapter(command entities.Command, entity entities.Entity) error {
	ent := entity.(*entities.BinaryAnalysis)
	assert.Len(command.T, ent.Results, 14)
	assert.Len(command.T, ent.Libraries, 4)
	assert.Equal(command.T, entities.ObjC, ent.BinType)
	assert.Equal(command.T, entities.Bits64, ent.Macho.Bits)
	assert.Equal(command.T, entities.BigEndian, ent.Macho.Endianness)
	assert.Equal(command.T, entities.X8664, ent.Macho.Cpu)
	return nil
}

func TestAnalysis(t *testing.T) {
	ipaPath, _ := test.FindTest("usecases", "binary", "binary.ipa")
	var (
		command = entities.Command{
			Path: ipaPath,
			T:    t,
		}
		entity  = entities.BinaryAnalysis{}
		adapter = mocks.GetTestMap(binaryTestAdapter)
	)
	Analysis(command, &entity, adapter)
}
