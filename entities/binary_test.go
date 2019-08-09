package entities

import "testing"

var (
	machoInfoTestMap = map[string]interface{}{
		"bits": 32,
		"endianness": "BigEndian",
		"cpu": "i386",
		"sub_cpu": "CPU_SUBTYPE_PENTIUM_M",
	}

	wrongMachoInfoTestMap = map[string]interface{}{
		"bits": uint(17),
		"endianness": "Something",
		"cpu": "i386",
		"sub_cpu": "CPU_SUBTYPE_PENTIUM_M",
	}

)

func TestMachoInfoMapTransformation(t *testing.T) {
	macho := &MachoInfo{}
	p := macho.FromMap(wrongMachoInfoTestMap)
	t.Error(p)
}

func TestBinaryAnalysisResultMapTranformation(t *testing.T) {

}

func TestBinaryAnalysisMapTransformation(t *testing.T) {

}
