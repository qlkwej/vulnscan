package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	toolUrlsTestMap = map[string]interface{}{
		"j_tool": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool",
		"class_dump_z": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-z",
		"class_dump_swift": "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-swift",
	}

	wrongToolUrlsTestMap = map[string]interface{}{
		"j_tool": "github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool",
		"class_dump_z": "definitelly/not/an/url",
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
