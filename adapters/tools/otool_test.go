package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOtoolAdapters(t *testing.T) {
	path, _ := test.FindTest("adapters", "tools", "otool", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: path, Source: false}, func(p string) error {
		command := entities.Command{Path: p, AppName: "iVim"}
		assert.NoError(t, framework.ExtractBinPath(&command))
		command.Tools, _ = test.FindTools()
		entity := entities.BinaryAnalysis{}
		assert.NoError(t, OtoolHeaderAdapter(command, &entity))
		assert.NoError(t, OtoolLibsAdapter(command, &entity))
		assert.NoError(t, OtoolSymbolsAdapter(command, &entity))
		assert.Len(t, entity.Libraries, 25)
		assert.Len(t, entity.Results, 12)
		return nil
	}))
}
