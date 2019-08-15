package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	storeResultTestMap = map[string]interface{}{
		"features":         	[]string{"iosUniversal"},
		"icon_url_512": 		"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/512x512bb.jpg",
		"icon_url_100":			"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/100x100bb.jpg",
		"icon_url_60": 			"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/60x60bb.jpg",
		"developer_id": 		48188146,
		"developer_name":		"Edison Software Inc.",
		"developer_url": 		"https://apps.apple.com/us/developer/edison-software-inc/id481881468?uo=4",
		"developer_website":	"http://mail.edison.tech",
		"supported_devices": 	[]string{"iPhone5-iPhone5", "iPadFourthGen-iPadFourthGen", "iPadFourthGen4G-iPadFourthGen4G"},
		"title":				"Email - Edison Mail",
		"app_id":				"com.easilydo.mail",
		"categories":			[]string{"Productivity", "Business"},
		"description": 			"Description",
		"price":				0.0,
		"url":					"https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4",
		"score":				4.5,
	}
	wrongStoreResultMap = map[string]interface{}{
		"developer_id": 		48188146,
		"developer_url": 		"https://apps.apple.com/us/developer/edison-software-inc/id481881468?uo=4",
		"developer_website":	"http://mail.edison.tech",
		"app_id":				"com.easilydo.mail",
		"categories":			[]string{"Productivity", "Business"},
		"description": 			"Description",
		"price":				0.0,
		"url":					"https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4",
		"score":				4.5,
	}

	storeAnalysisTestMap = map[string]interface{}{
		"count": 1,
		"results": []map[string]interface{}{
			{
				"features":         	[]string{"iosUniversal"},
				"icon_url_512": 		"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/512x512bb.jpg",
				"icon_url_100":			"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/100x100bb.jpg",
				"icon_url_60": 			"https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/60x60bb.jpg",
				"developer_id": 		48188146,
				"developer_name":		"Edison Software Inc.",
				"developer_url": 		"https://apps.apple.com/us/developer/edison-software-inc/id481881468?uo=4",
				"developer_website":	"http://mail.edison.tech",
				"supported_devices": 	[]string{"iPhone5-iPhone5", "iPadFourthGen-iPadFourthGen", "iPadFourthGen4G-iPadFourthGen4G"},
				"title":				"Email - Edison Mail",
				"app_id":				"com.easilydo.mail",
				"categories":			[]string{"Productivity", "Business"},
				"description": 			"Description",
				"price":				0.0,
				"url":					"https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4",
				"score":				4.5,
			},
		},
	}

	wrongStoreAnalysisTestMap = map[string]interface{}{
		"count": 0,
		"results": []map[string]interface{}{},
	}
)


func TestStoreResultTransformation(t *testing.T) {
	p, err := (&StoreResult{}).FromMap(storeResultTestMap)
	assert.NoError(t, err)
	assert.Equal(t, storeResultTestMap, p.ToMap())
}

func TestStoreResultValidation(t *testing.T) {
	p, err := (&StoreResult{}).FromMap(storeResultTestMap)
	assert.NoError(t, err)
	t.Logf("%#v", p)
	assert.Len(t, p.Validate(), 0)
	p, err = (&StoreResult{}).FromMap(wrongStoreResultMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 7)
}


func TestStoreAnalysisTransformation(t *testing.T) {
	p, err := (&StoreAnalysis{}).FromMap(storeAnalysisTestMap)
	assert.NoError(t, err)
	assert.Equal(t, storeAnalysisTestMap, p.ToMap())
}

func TestStoreAnalysisValidation(t *testing.T) {
	p, err := (&StoreAnalysis{}).FromMap(storeAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&StoreAnalysis{}).FromMap(wrongStoreAnalysisTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}
