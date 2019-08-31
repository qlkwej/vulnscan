package files

import (
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func codeTestAdapter(command entities.Command, entity entities.Entity) error {
	ent := entity.(*entities.FileAnalysis)
	assert.Empty(command.T, ent.Certifications)
	assert.Empty(command.T, ent.Databases)
	assert.NotEmpty(command.T, ent.PLists)
	assert.NotEmpty(command.T, ent.Files)
	return nil
}

func TestAnalysis(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "source.zip")
	path, _ := utils.FindTest("apps", "source")
	assert.NoError(t, utils.WithUnzip(zipFile, path, func(p string) error {
		Analysis(
			entities.Command{
				Path:   p,
				Source: false,
				T:      t,
			},
			&entities.FileAnalysis{},
			mocks.GetTestMap(codeTestAdapter),
		)
		return nil
	}))
}
