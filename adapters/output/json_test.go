package output

import (
	"bytes"
	"encoding/json"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJsonAdapter(t *testing.T) {
	var (
		buffer  bytes.Buffer
		command = entities.Command{
			Output: &buffer,
		}
	)
	assert.NoError(t, JsonAdapter(command, &binaryAnalysisTest))
	entity := entities.BinaryAnalysis{}
	assert.NoError(t, json.Unmarshal(buffer.Bytes(), &entity))
	assert.Equal(t, binaryAnalysisTest, entity)
}
