package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClassDumpAdapter(t *testing.T) {
	path, _ := test.FindTest("adapters", "tools", "class_dump", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: path}, func(p, sp string) error {
		command := entities.Command{Path: p, AppName: "iVim"}
		assert.NoError(t, framework.ExtractBinPath(&command))
		command.Tools, _ = test.FindTools()
		entity := entities.BinaryAnalysis{}
		assert.NoError(t, ClassDumpAdapter(command, &entity))
		assert.Equal(t, "Binary doesn't use WebView Component.", entity.Results[0].Issue)
		return nil
	}))
}
