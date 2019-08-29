package code

import (
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func codeTestAdapter(command utils.Command, entity entities.Entity) error {
	ent := entity.(*entities.CodeAnalysis)
	assert.NotEmpty(command.T, ent.Codes)
	assert.NotEmpty(command.T, ent.Apis)
	assert.NotEmpty(command.T, ent.Urls)
	assert.NotEmpty(command.T, ent.Emails)
	assert.Equal(command.T, 7, len(ent.BadDomains))
	return nil
}

func TestAnalysis(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "vulnerable_app.zip")
	path, _ := utils.FindTest("apps", "vulnerable_app")
	assert.NoError(t, utils.WithUnzip(zipFile, path, func(p string) error {
		Analysis(utils.Command{
			Path:          p,
			Source:        false,
			CheckDomains:  true,
			T:             t,
		},
		&entities.CodeAnalysis{},
		mocks.GetTestMap(codeTestAdapter))
		return nil
	}))
}

