package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	virusAnalysisWithReportTestMap = map[string]interface {}{
		"md5":       "b956666c9670cff7166d28af88a3e063",
		"permalink": "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
		"resource":      "b956666c9670cff7166d28af88a3e063",
		"response_code": 1,
		"scan_date":     "2019-08-12 23:52:39",
		"scan_id": "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
		"sha1":"01d4f5b3a7d81a02c8be039124c08a0e389f3eb3",
		"sha256":"11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
		"total":54,
		"positives": 0,
		"verbose_msg":"Scan finished, information embedded",
		"scans": map[string]interface{}{
			"ALYac": map[string]interface{}{
				"detected": false,
				"result":   "",
				"update":   "20190812",
				"version":  "1.1.1.5",
			},
			"Ad-Aware": map[string]interface{}{
				"detected": false,
				"result":   "",
				"update":   "20190813",
				"version":  "3.0.5.370",
			},
		},
	}

	virusAnalysisWithoutReportTestMap = map[string]interface {}{
		"permalink": "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
		"resource":      "b956666c9670cff7166d28af88a3e063",
		"response_code": 1,
		"scan_id": "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
		"sha256":"11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
		"verbose_msg":"Scan finished, information embedded",
	}
	wrongVirusAnalysisTestMap = map[string]interface{}{
		"total":54,
		"positives": 0,
		"verbose_msg":"Scan finished, information embedded",
		"scans": map[string]interface{}{
			"ALYac": map[string]interface{}{
				"detected": false,
				"result":   "",
				"update":   "20190812",
				"version":  "1.1.1.5",
			},
			"Ad-Aware": map[string]interface{}{
				"detected": false,
				"result":   "",
				"update":   "20190813",
				"version":  "3.0.5.370",
			},
		},
	}
)

func TestVirusAnalysisTransformation(t *testing.T) {
	p, err := (&VirusAnalysis{}).FromMap(virusAnalysisWithReportTestMap)
	assert.NoError(t, err)
	t.Logf("%#v", p)
	assert.Equal(t, virusAnalysisWithReportTestMap, p.ToMap())
	p, err = (&VirusAnalysis{}).FromMap(virusAnalysisWithoutReportTestMap)
	assert.NoError(t, err)
	assert.Equal(t, virusAnalysisWithoutReportTestMap, p.ToMap())
}

func TestVirusAnalysisWithReportValidation(t *testing.T) {
	p, err := (&VirusAnalysis{}).FromMap(virusAnalysisWithReportTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&VirusAnalysis{}).FromMap(virusAnalysisWithoutReportTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&VirusAnalysis{}).FromMap(wrongVirusAnalysisTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 4)
}
