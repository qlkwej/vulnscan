package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var messageTestMap = map[string]interface{}{
	"level":    1,
	"analysis": "Binary Analysis",
	"message":  "Message to log",
}

func TestMessageTransformation(t *testing.T) {
	p, err := (&LogMessage{}).FromMap(messageTestMap)
	assert.NoError(t, err)
	assert.Equal(t, messageTestMap, p.ToMap())
}
