package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestOtoolAdapters(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	assert.NoError(t, utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		assert.NoError(t, err)
		binPath := filepath.Join(appPath, "iVim")

		var (
			command = utils.Command{ Path: binPath }
			entity = entities.BinaryAnalysis{}
		)
		assert.NoError(t, OtoolHeaderAdapter(command, &entity))
		assert.NoError(t, OtoolLibsAdapter(command, &entity))
		assert.NoError(t, OtoolSymbolsAdapter(command, &entity))
		assert.Len(t, entity.Libraries, 25)
		assert.Len(t, entity.Results, 12)
		return nil
	}))
}

