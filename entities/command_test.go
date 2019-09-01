package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var commandTestMap = map[string]interface{}{
	"path": "/usr/app/binary",
	"tools": "/var/tools/folder",
	"app_name": "Binary",
	"app_id": "183948394",
	"country": "us",
	"virus_total_key": "XXXXX-XXXXXX-XXXXXX-XXXXXX",
	"source": false,
	"analysis": map[string]bool{
		"DoPList": true,
		"DoFiles": false,
	},
}

func TestCommandMapTransformation(t *testing.T) {
	command, err := Command{}.FromMap(commandTestMap)
	assert.NoError(t, err)
	commandMap := command.ToMap()
	delete(commandMap, "t")
	delete(commandMap, "output")
	assert.Equal(t, commandTestMap, commandMap)
}

func TestCommandMapValidation(t *testing.T) {
	command, _ := Command{}.FromMap(commandTestMap)
	assert.Empty(t, command.Validate())
	invalidCommand := Command{
		Path:     "",
		Analysis: map[AnalysisCheck]bool{AnalysisCheck("Something"): false},
	}
	assert.Len(t, invalidCommand.Validate(), 3)
}
