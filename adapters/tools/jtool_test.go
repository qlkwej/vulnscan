package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJtoolAdapters(t *testing.T) {
	path, _ := test.FindTest("adapters", "tools", "jtool", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: path, Source: false}, func(p, sp string) error {
		command := entities.Command{Path: p, AppName: "iVim"}
		assert.NoError(t, framework.ExtractBinPath(&command))
		command.Tools, _ = test.FindTools()
		entity := entities.BinaryAnalysis{}
		assert.NoError(t, JtoolHeadersAdapter(command, &entity))
		assert.NoError(t, JtoolLibsAdapter(command, &entity))
		assert.NoError(t, JtoolSymbolsAdapter(command, &entity))
		assert.NoError(t, JtoolClassDumpAdapter(command, &entity))
		assert.Len(t, entity.Libraries, 23)
		assert.Len(t, entity.Results, 13)
		return nil
	}))
}
