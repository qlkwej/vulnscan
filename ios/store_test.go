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
	testStoreLookup := map[string]interface{}{}
	sampleLookupFile, _ := ioutil.ReadFile("sample-store-lookup.json")
	_ = json.Unmarshal([]byte(sampleLookupFile), &testStoreLookup)
	// Assert the number of results is right
	if count := searchResult["count"]; count != 1 {
		t.Errorf("Search result = %d; wanted 1", count)
	}
	// And check some fields of the result (the ones that are more unlikely to change)
	var sb strings.Builder
	var errorCount int
	searchResultValue := searchResult["results"].([]map[string]interface{})[0]
	testResultValue := testStoreLookup["results"].([]interface{})[0].(map[string]interface{})
	for k, v := range map[string]string{
		"developer_id":      "artistId",
		"developer_name":    "artistName",
		"developer_url":     "artistViewUrl",
		"developer_website": "sellerUrl",
		"title":             "trackName",
		"app_id":            "bundleId",
		"categories":        "genres",
		"price":             "price",
		"url":               "trackViewUrl",
	} {
		if sF, tF := searchResultValue[v], testResultValue[k]; !reflect.DeepEqual(sF, tF) {
			errorCount += 1
			sb.WriteString(fmt.Sprintf("%s: expected value -> %s, found value -> %s\n", v, tF, sF))
		}
	}
	if errorCount > 0 {
		t.Errorf("Found %d missmatches between in field result \n %s", errorCount, sb.String())
	}
}
