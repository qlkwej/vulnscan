package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)


func TestDownloaderAdapter(t *testing.T) {
	var (
		p, _ = test.FindTest()
		command = entities.Command{Tools: p}
		entity = entities.ToolUrls{
			JTool:          framework.JtoolUrl,
			ClassDumpZ:     framework.ClassDumpZUrl,
			ClassDumpSwift: framework.ClassDumpSwiftUrl,
		}
	)
	assert.NoError(t, DownloaderAdapter(command, &entity))
	for k, _ := range entity.ToMap() {
		tPath := filepath.Join(p, k)
		_, err := os.Stat(tPath)
		assert.False(t, os.IsNotExist(err))
		err = os.Remove(tPath)
		assert.NoError(t, err)
	}
}
