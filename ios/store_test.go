package ios

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
)

func TestSearch(t *testing.T) {
	// Call method
	searchResult := Search("com.easilydo.mail", "us")
	// And get comparable value
	testStoreLookup := SearchResult{}
	sampleLookupFile, _ := ioutil.ReadFile("sample-store-lookup.json")
	_ = json.Unmarshal([]byte(sampleLookupFile), &testStoreLookup)
	// Assert the number of results is right
	if count := searchResult.ResultCount; count != 1 {
		t.Errorf("Search result = %d; wanted 1", count)
	}
	// And check some fields of the result (the ones that are more unlikely to change)
	var sb strings.Builder
	var errorCount int
	searchResultValue := reflect.ValueOf(searchResult.Results[0])
	testResultValue := reflect.ValueOf(testStoreLookup.Results[0])
	for _, name := range []string{
		"DeveloperID", "DeveloperName", "DeveloperURL", "DeveloperWebsite", "Title", "AppID", "Categories", "Price",
		"ItunesURL"} {
		if sF, tF := searchResultValue.FieldByName(name).Interface(), testResultValue.FieldByName(name).Interface();
			!reflect.DeepEqual(sF, tF) {
			errorCount += 1
			sb.WriteString(fmt.Sprintf("%s: expected value -> %s, found value -> %s\n", name, tF, sF))
		}
	}
	if errorCount > 0 {
		t.Errorf("Found %d missmatches between in field result \n %s", errorCount, sb.String())
	}
}
