package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)


func TestClassDumpAdapter(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	assert.NoError(t, utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		assert.NoError(t, err)
		binPath := filepath.Join(appPath, "iVim")
		var (
			command = utils.Command{ Path: binPath }
			entity = entities.BinaryAnalysis{}
		)
		assert.NoError(t, ClassDumpAdapter(command, &entity))
		assert.Equal(t, "Binary doesn't use WebView Component.", entity.Results[0].Issue)
		return nil
	}))
}
