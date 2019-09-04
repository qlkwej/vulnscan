package plist

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/framework"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func codeTestAdapter(command entities.Command, entity entities.Entity) error {
	ent := entity.(*entities.PListAnalysis)
	assert.NotEmpty(command.T, ent.Xml)
	return nil
}

func TestPlistSearch(t *testing.T) {
	// Source
	zipFile, _ := test.FindTest("usecases", "plist", "source.zip")
	assert.NoError(t, framework.Normalize(entities.Command{Path: zipFile, Source: false}, func(p string) error {
		command := entities.Command{
			Path:   p,
			Source: true,
			T:      t,
		}
		assert.NoError(t, findPListFile(&command))
		_, err := os.Stat(command.Path)
		assert.False(t, os.IsNotExist(err))
		assert.Equal(t, ".plist", filepath.Ext(command.Path))
		return nil
	}))
	// Binary
	zipFile, _ = test.FindTest("usecases", "plist", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: zipFile, Source: false}, func(p string) error {
		command := entities.Command{
			Path:   p,
			Source: false,
			T:      t,
		}
		assert.NoError(t, findPListFile(&command))
		_, err := os.Stat(command.Path)
		assert.False(t, os.IsNotExist(err))
		assert.Equal(t, ".plist", filepath.Ext(command.Path))
		return nil
	}))
}

func TestMakeAnalysis(t *testing.T) {
	var adapter = mocks.GetTestMap(codeTestAdapter)
	for i := 1; i <= 5; i++ {
		path, _ := test.FindTest("usecases", "plist", fmt.Sprintf("plist%d.plist", i))
		makePListAnalysis(
			entities.Command{
				Path: path,
				T:    t,
			},
			&entities.PListAnalysis{},
			adapter)
	}
}

func TestAnalysis(t *testing.T) {
	var adapter = mocks.GetTestMap(codeTestAdapter)
	// Source
	zipFile, _ := test.FindTest("usecases", "plist", "source.zip")
	assert.NoError(t, framework.Normalize(entities.Command{Path: zipFile, Source: false}, func(p string) error {
		Analysis(
			entities.Command{
				Path:   p,
				Source: true,
				T:      t,
			},
			&entities.PListAnalysis{},
			adapter,
		)
		return nil
	}))
	// Binary
	zipFile, _ = test.FindTest("usecases", "plist", "binary.ipa")
	assert.NoError(t, framework.Normalize(entities.Command{Path: zipFile, Source: false}, func(p string) error {
		Analysis(
			entities.Command{
				Path:   p,
				Source: true,
				T:      t,
			},
			&entities.PListAnalysis{},
			adapter,
		)
		return nil
	}))
}
