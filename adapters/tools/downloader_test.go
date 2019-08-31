package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)


func TestDownloaderAdapter(t *testing.T) {
	var (
		p, _ = utils.FindTest()
		command = entities.Command{Tools: p}
		entity = entities.ToolUrls{
			JTool:          utils.JtoolUrl,
			ClassDumpZ:     utils.ClassDumpZUrl,
			ClassDumpSwift: utils.ClassDumpSwiftUrl,
		}
	)
	assert.NoError(t, DownloaderAdapter(command, &entity))
	for k, _ := range entity.ToMap() {
		tPath := fmt.Sprintf("%s/%s", p, k)
		_, err := os.Stat(tPath)
		assert.False(t, os.IsNotExist(err))
		err = os.Remove(tPath)
		assert.NoError(t, err)
	}
}
