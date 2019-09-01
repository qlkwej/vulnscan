package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestClassDumpAdapter(t *testing.T) {
	path, _ := test.FindTest("adapters", "tools", "class_dump", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: path, Source:false}, func(p string) error {
		command := entities.Command{ Path: p, AppName: "iVim"}
		assert.NoError(t, framework.ExtractBinPath(&command))
		mainFolder, _ := test.FindMainFolder()
		command.Tools = filepath.Join(mainFolder, "tools")
		entity  := entities.BinaryAnalysis{}
		assert.NoError(t, ClassDumpAdapter(command, &entity))
		assert.Equal(t, "Binary doesn't use WebView Component.", entity.Results[0].Issue)
		return nil
	}))
}
