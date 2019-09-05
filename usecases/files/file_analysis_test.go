package files

import (
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
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
	zipFile, _ := test.FindTest("usecases", "files", "source.zip")
	assert.NoError(t, framework.Normalize(entities.Command{Path: zipFile, Source: false}, func(p string) error {
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
