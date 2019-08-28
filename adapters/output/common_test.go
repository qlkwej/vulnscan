package output

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseError(t *testing.T) {
	err := fmt.Errorf("everyone can make a mistake")
	c, e := ParseError(entities.Code, err)
	assert.Equal(t, utils.Command{}, c)
	assert.Equal(t, &entities.Error{
		Analysis: entities.Code,
		E:        err,
	}, e)
}

func TestParseInfo(t *testing.T) {
	info := "breaking news are not so breaking anymore"
	c, e := ParseInfo(entities.Plist, info)
	assert.Equal(t, utils.Command{}, c)
	assert.Equal(t, &entities.LogMessage{
		Level:    entities.Inf,
		Analysis: entities.Plist,
		Message:  info,
	}, e)
}

func TestParseWarning(t *testing.T) {
	info := "may I have your attention please"
	c, e := ParseWarning(entities.Plist, info)
	assert.Equal(t, utils.Command{}, c)
	assert.Equal(t, &entities.LogMessage{
		Level:    entities.Warn,
		Analysis: entities.Plist,
		Message:  info,
	}, e)
}
