package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	machoInfoTestMap = map[string]interface{}{
		"bits":       uint(32),
		"endianness": "BigEndian",
		"cpu":        "i386",
		"sub_cpu":    "CPU_SUBTYPE_PENTIUM_M",
	}

	wrongMachoInfoTestMap = map[string]interface{}{
		"bits":       uint(17),
		"endianness": "Something",
		"cpu":        "i386",
		"sub_cpu":    "CPU_SUBTYPE_PENTIUM_M",
	}

	binaryAnalysisResultMap = map[string]interface{}{
		"issue":       "There is an issue",
		"description": "A very bad issue",
		"status":      "insecure",
		"cvss":        10.8,
		"cwe":         "CWE-144",
	}

	wrongBinaryAnalysisResultMap = map[string]interface{}{
		"issue":       "There is an issue",
		"description": "A very bad issue",
		"status":      "fantastic",
		"cvss":        10.8,
		"cwe":         "144",
	}

	binaryAnalysisMap = map[string]interface{}{
		"libraries": []string{"a library", "some other library", "an even better library"},
		"macho":     machoInfoTestMap,
		"results": []map[string]interface{}{
			binaryAnalysisResultMap,
		},
		"bin_type": "Swift",
	}

	wrongBinaryAnalysisMap = map[string]interface{}{
		"libraries": []string{},
		"macho":     wrongMachoInfoTestMap,
		"results": []map[string]interface{}{
			wrongBinaryAnalysisResultMap,
		},
		"bin_type": "Rust",
	}
)

func TestMachoInfoMapTransformation(t *testing.T) {
	macho := &MachoInfo{}
	p, err := macho.FromMap(machoInfoTestMap)
	assert.NoError(t, err)
	assert.Equal(t, p.ToMap(), machoInfoTestMap)
}

func TestMachoInfoValidation(t *testing.T) {
	p, err := (&MachoInfo{}).FromMap(machoInfoTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&MachoInfo{}).FromMap(wrongMachoInfoTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}

func TestBinaryAnalysisResultMapTranformation(t *testing.T) {
	result := BinaryAnalysisResult{}
	r, err := result.FromMap(binaryAnalysisResultMap)
	assert.NoError(t, err)
	assert.Equal(t, binaryAnalysisResultMap, r.ToMap())
}

func TestBinaryAnalysisResultMapValidation(t *testing.T) {
	r, err := (&BinaryAnalysisResult{}).FromMap(binaryAnalysisResultMap)
	assert.NoError(t, err)
	assert.Len(t, r.Validate(), 0)
	r, err = (&BinaryAnalysisResult{}).FromMap(wrongBinaryAnalysisResultMap)
	assert.NoError(t, err)
	assert.Len(t, r.Validate(), 2)
}

func TestBinaryAnalysisMapTransformation(t *testing.T) {
	analysis := BinaryAnalysis{}
	a, err := analysis.FromMap(binaryAnalysisMap)
	assert.NoError(t, err)
	assert.Equal(t, binaryAnalysisMap, a.ToMap())
}

func TestBinaryAnalysisValidatiom(t *testing.T) {
	a, err := (&BinaryAnalysis{}).FromMap(binaryAnalysisMap)
	assert.NoError(t, err)
	assert.Len(t, a.Validate(), 0)
	a, err = (&BinaryAnalysis{}).FromMap(wrongBinaryAnalysisMap)
	assert.NoError(t, err)
	assert.Len(t, a.Validate(), 3)
}
