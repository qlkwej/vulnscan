package code

import (
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func codeTestAdapter(command entities.Command, entity entities.Entity) error {
	ent := entity.(*entities.CodeAnalysis)
	assert.NotEmpty(command.T, ent.Codes)
	assert.NotEmpty(command.T, ent.Apis)
	assert.NotEmpty(command.T, ent.Urls)
	assert.NotEmpty(command.T, ent.Emails)
	assert.Equal(command.T, 7, len(ent.BadDomains))
	return nil
}

func TestAnalysis(t *testing.T) {
	zipFile, _ := test.FindTest("usecases", "code", "vulnerable_app.zip")
	assert.NoError(t, framework.Normalize(entities.Command{SourcePath: zipFile}, func(p, sp string) error {
		Analysis(entities.Command{
			SourcePath: sp,
			Source:     true,
			T:          t,
		},
			&entities.CodeAnalysis{},
			mocks.GetTestMap(codeTestAdapter))
		return nil
	}))
}
