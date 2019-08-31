package output

import (
	"bytes"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicErrorAdapter(t *testing.T) {
	var (
		buffer   = bytes.Buffer{}
		command  = utils.Command{}
		errorEnt = entities.Error{
			Analysis: entities.Code,
			E:        fmt.Errorf("this is the way the word ends, not with a bang but a whimper"),
		}
	)
	SetBasicLogger(&buffer, entities.Err, false)
	assert.Error(t, BasicErrorAdapter(command, &errorEnt))
	assert.Equal(t, "ERROR| Code Analysis: this is the way the word ends, not with a bang but a whimper\n", buffer.String())
}
