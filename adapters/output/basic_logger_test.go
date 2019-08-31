package output

import (
	"bytes"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicLoggerAdapter(t *testing.T) {
	var (
		buffer      = bytes.Buffer{}
		command     = utils.Command{}
		infoMessage = entities.LogMessage{
			Level:    entities.Info,
			Analysis: entities.Code,
			Message:  "a very informative note, sir",
		}
		warnMessage = entities.LogMessage{
			Level:    entities.Warn,
			Analysis: entities.Plist,
			Message:  "be careful with wath you wish",
		}
		errorMessage = entities.LogMessage{
			Level:    entities.Err,
			Analysis: entities.None,
			Message:  "last Star Wars trilogy is awesome",
		}
	)
	SetBasicLogger(&buffer, entities.Info, false)
	assert.NoError(t, BasicLoggerAdapter(command, &infoMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &warnMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &errorMessage))
	assert.Equal(t,
		"INFO| Code Analysis: a very informative note, sir\n"+
			"WARNING| Plist Analysis: be careful with wath you wish\n"+
			"ERROR| last Star Wars trilogy is awesome\n",
		buffer.String())

	buffer.Reset()
	SetBasicLogger(&buffer, entities.Warn, false)
	assert.NoError(t, BasicLoggerAdapter(command, &infoMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &warnMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &errorMessage))
	assert.Equal(t,
		"WARNING| Plist Analysis: be careful with wath you wish\n"+
			"ERROR| last Star Wars trilogy is awesome\n",
		buffer.String())

	buffer.Reset()
	SetBasicLogger(&buffer, entities.Err, false)
	assert.NoError(t, BasicLoggerAdapter(command, &infoMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &warnMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &errorMessage))
	assert.Equal(t, "ERROR| last Star Wars trilogy is awesome\n", buffer.String())

	buffer.Reset()
	SetBasicLogger(&buffer, entities.Undefined, true)
	assert.NoError(t, BasicLoggerAdapter(command, &infoMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &warnMessage))
	assert.NoError(t, BasicLoggerAdapter(command, &errorMessage))
	assert.Equal(t, "", buffer.String())
}
