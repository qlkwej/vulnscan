package store

import (
	"encoding/json"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func storeTestAdapter(command utils.Command, entity entities.Entity) error {
	ent := entity.(*entities.StoreAnalysis)
	sampleStoreResultPath, _ := utils.FindTest("sample-store-lookup.json")
	sampleLookupFile, _ := ioutil.ReadFile(sampleStoreResultPath)
	comparisonEntity := entities.StoreAnalysis{}
	assert.NoError(command.T, json.Unmarshal(sampleLookupFile, &comparisonEntity))
	comparisonResult := comparisonEntity.Results[0]
	result := ent.Results[0]
	assert.Equal(command.T, ent.Count, len(ent.Results))
	assert.Equal(command.T, comparisonResult.Features, result.Features)
	assert.Equal(command.T, comparisonResult.DeveloperWebsite, result.DeveloperWebsite)
	assert.Equal(command.T, comparisonResult.Title, result.Title)
	assert.Equal(command.T, comparisonResult.AppId, result.AppId)
	assert.Equal(command.T, comparisonResult.Categories, result.Categories)
	assert.Equal(command.T, comparisonResult.Price, result.Price)
	assert.Equal(command.T, comparisonResult.Url, result.Url)
	return nil
}

func TestAnalysis(t *testing.T) {
	Analysis(
		utils.Command{
			AppId:   "com.easilydo.mail",
			Country: "us",
			T:       t,
		},
		&entities.StoreAnalysis{},
		mocks.GetTestMap(storeTestAdapter),
	)
}
