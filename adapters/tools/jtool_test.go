package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestJtoolAdapters(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	assert.NoError(t, utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		assert.NoError(t, err)
		binPath := filepath.Join(appPath, "iVim")

		var (
			command = entities.Command{Path: binPath}
			entity  = entities.BinaryAnalysis{}
		)

		assert.NoError(t, JtoolHeadersAdapter(command, &entity))
		assert.NoError(t, JtoolLibsAdapter(command, &entity))
		assert.NoError(t, JtoolSymbolsAdapter(command, &entity))
		assert.NoError(t, JtoolClassDumpAdapter(command, &entity))
		assert.Len(t, entity.Libraries, 25)
		assert.Len(t, entity.Results, 13)
		return nil
	}))
}
