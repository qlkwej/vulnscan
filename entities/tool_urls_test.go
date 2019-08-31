package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	toolUrlsTestMap = map[string]interface{}{
		"jtool": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool",
		"class-dump-z": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-z",
		"class-dump-swift": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-swift",
	}

	wrongToolUrlsTestMap = map[string]interface{}{
		"jtool": "github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool",
		"class-dump-z": "definitelly/not/an/url",
	}
)

func TestToolUrlsMapTransformation(t *testing.T) {
	p, err := (&ToolUrls{}).FromMap(toolUrlsTestMap)
	assert.NoError(t, err)
	assert.Equal(t, toolUrlsTestMap, p.ToMap())
}

func TestToolUrlsValidation(t *testing.T) {
	p, err := (&ToolUrls{}).FromMap(toolUrlsTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&ToolUrls{}).FromMap(wrongToolUrlsTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 3)
}
