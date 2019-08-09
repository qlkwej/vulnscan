package entities

import "gopkg.in/go-playground/validator.v9"

type (
	Bits       uint
	Endianness string
	CpuType    string
	SubCpuType string
	Status     string
	CWE		   string


	MachoInfo struct {
		Bits       Bits 		`json:"bits" validate:"required oneof=32 64"`
		Endianness Endianness 	`json:"endianness" validate:"required oneof=BigEndian LittleEndian"`
		Cpu        CpuType 		`json:"cpu" validate:"required oneof=VAX "`
		SubCpu     SubCpuType 	`json:"sub_cpu"`
	}

	BinaryAnalysisResult struct {
		Issue         string 	`json:"issue"`
		Description   string 	`json:"description"`
		Status        Status 	`json:"status"`
		Cvss		  float32 	`json:"cvss"`
		CWE           CWE 		`json:"cwe"`
	}

	BinaryAnalysis struct {
		Libraries      []string 				`json:"libraries"`
		Macho          MachoInfo 				`json:"macho"`
		Results		   []BinaryAnalysisResult 	`json:"results"`
	}
)

const (

	Bits32 Bits = 32
	Bits64 Bits = 64

	BigEndian 	 Endianness = "BigEndian"
	LittleEndian Endianness = "LittleEndian"

	Secure Status = "Secure"
	Insecure Status = "Insecure"
	Info Status = "Info"
	Warning Status = "Warning"

	VAX 		CpuType = "VAX"
	MC680X0 	CpuType = "MC680x0"
	I386 		CpuType = "i386"
	X8664 		CpuType = "x86_64"
	MIPS 		CpuType = "MIPS"
	MC98000 	CpuType = "MC98000"
	HPPA 		CpuType = "HPPA"
	ARM 		CpuType = "ARM"
	ARM64 		CpuType = "ARM64"
	MC88000 	CpuType = "MC88000"
	SPARC 		CpuType = "SPARC"
	I860 		CpuType = "i860"
	Alpha 		CpuType = "Alpha"
	PowerPC 	CpuType = "PowerPC"
	PowerPC64 	CpuType = "PowerPC64"

	IntelModelAll	SubCpuType = "CPU_SUBTYPE_INTEL_MODEL_ALL"
	IntelHTT 		SubCpuType = "CPU_THREADTYPE_INTEL_HTT"
	I386All 		SubCpuType = "CPU_SUBTYPE_I386_ALL"
	I486 			SubCpuType = "CPU_SUBTYPE_486"
	I586 			SubCpuType = "CPU_SUBTYPE_586"
	Pentium3 		SubCpuType = "CPU_SUBTYPE_PENTIUM_3"
	PentiumM 		SubCpuType = "CPU_SUBTYPE_PENTIUM_M"
	Pentium4 		SubCpuType = "CPU_SUBTYPE_PENTIUM_4"
	Itanium 		SubCpuType = "CPU_SUBTYPE_ITANIUM"
	Xeon 			SubCpuType = "CPU_SUBTYPE_XEON"
	XeonMP 			SubCpuType = "CPU_SUBTYPE_XEON_MP"
	Pentium4M 		SubCpuType = "CPU_SUBTYPE_PENTIUM_4_M"
	Itanium2 		SubCpuType = "CPU_SUBTYPE_ITANIUM_2"
	PentiumPro 		SubCpuType = "CPU_SUBTYPE_PENTPRO"
	Pentium3M 		SubCpuType = "CPU_SUBTYPE_PENTIUM_3_M"
	Pentium3Xeon 	SubCpuType = "CPU_SUBTYPE_PENTIUM_3_XEON"
	PentiiM3 		SubCpuType = "CPU_SUBTYPE_PENTII_M3"
	I486Sx 			SubCpuType = "CPU_SUBTYPE_486SX"
	PentiiM5 		SubCpuType = "CPU_SUBTYPE_PENTII_M5"
	Celeron 		SubCpuType = "CPU_SUBTYPE_CELERON"
	CeleronMobile 	SubCpuType = "CPU_SUBTYPE_CELERON_MOBILE"

	X8664All 		SubCpuType = "CPU_SUBTYPE_X86_64_ALL"
	X86Arch1		SubCpuType = "CPU_SUBTYPE_X86_ARCH1"

	MipsAll			SubCpuType = "CPU_SUBTYPE_MIPS_ALL"
	MipsR2300		SubCpuType = "CPU_SUBTYPE_MIPS_R2300"
	MipsR2600		SubCpuType = "CPU_SUBTYPE_MIPS_R2600"
	MipsR2800		SubCpuType = "CPU_SUBTYPE_MIPS_R2800"
	MipsR2000a		SubCpuType = "CPU_SUBTYPE_MIPS_R2000a"
	MipsR2000		SubCpuType = "CPU_SUBTYPE_MIPS_R2000"
	MipsR3000a		SubCpuType = "CPU_SUBTYPE_MIPS_R3000a"
	MipsR3000		SubCpuType = "CPU_SUBTYPE_MIPS_R3000"

	MC680X0All 		SubCpuType = "CPU_SUBTYPE_MC680x0_ALL"
	MC68040 		SubCpuType = "CPU_SUBTYPE_MC68040"
	MC68030Only 	SubCpuType = "CPU_SUBTYPE_MC68030_ONLY"

	MC98000All 		SubCpuType = "CPU_SUBTYPE_MC98000_ALL"
	MC98601 		SubCpuType = "CPU_SUBTYPE_MC98601"

	Hppa7100 		SubCpuType = "CPU_SUBTYPE_HPPA_7100"
	Hppa7100LC 		SubCpuType = "CPU_SUBTYPE_HPPA_7100LC"

	Mc880000All SubCpuType = "CPU_SUBTYPE_MC88000_ALL"
	MC88100 SubCpuType = "CPU_SUBTYPE_MC88100"
	MC88110 SubCpuType = "CPU_SUBTYPE_MC88110"

	SparcAll SubCpuType = "CPU_SUBTYPE_SPARC_ALL"

	AlphaAll SubCpuType = "CPU_SUBTYPE_ALPHA_ALL"

	I860All SubCpuType = "CPU_SUBTYPE_I860_ALL"
	I860860 SubCpuType = "CPU_SUBTYPE_I860_860"

	PowerPCAll SubCpuType =  "CPU_SUBTYPE_POWERPC_ALL"
	PowerPC601 SubCpuType = "CPU_SUBTYPE_POWERPC_601"
	PowerPC602 SubCpuType = "CPU_SUBTYPE_POWERPC_602"
	PowerPC603 SubCpuType = "CPU_SUBTYPE_POWERPC_603"
	PowerPC603e SubCpuType = "CPU_SUBTYPE_POWERPC_603e"
	PowerPC603ev SubCpuType = "CPU_SUBTYPE_POWERPC_603ev"
	PowerPC604 SubCpuType = "CPU_SUBTYPE_POWERPC_604"
	PowerPC604e SubCpuType = "CPU_SUBTYPE_POWERPC_604e"
	PowerPC620 SubCpuType = "CPU_SUBTYPE_POWERPC_620"
	PowerPC750 SubCpuType = "CPU_SUBTYPE_POWERPC_750"
	PowerPC7400 SubCpuType = "CPU_SUBTYPE_POWERPC_7400"
	PowerPC7450 SubCpuType = "CPU_SUBTYPE_POWERPC_7450"
	PowerPC970 SubCpuType = "CPU_SUBTYPE_POWERPC_970"

	ArmAll12 SubCpuType = "CPU_SUBTYPE_ARM_ALL12"
	ArmV4T SubCpuType = "CPU_SUBTYPE_ARM_V4T"
	ArmV6 SubCpuType = "CPU_SUBTYPE_ARM_V6"
	ArmV5TEJ SubCpuType =  "CPU_SUBTYPE_ARM_V5TEJ"
	ArmXScale SubCpuType = "CPU_SUBTYPE_ARM_XSCALE"
	ArmV7 SubCpuType = "CPU_SUBTYPE_ARM_V7"
	ArmV7F SubCpuType = "CPU_SUBTYPE_ARM_V7F"
	ArmV7S SubCpuType = "CPU_SUBTYPE_ARM_V7S"
	ArmV7K SubCpuType = "CPU_SUBTYPE_ARM_V7K"
	ArmV6M SubCpuType = "CPU_SUBTYPE_ARM_V6M"
	ArmV7M SubCpuType = "CPU_SUBTYPE_ARM_V7M"
	ArmV7EM SubCpuType = "CPU_SUBTYPE_ARM_V7EM"

	VaxAll SubCpuType = "CPU_SUBTYPE_VAX_ALL"
	Vax780 SubCpuType = "CPU_SUBTYPE_VAX780"
	Vax785 SubCpuType = "CPU_SUBTYPE_VAX785"
	Vax750 SubCpuType = "CPU_SUBTYPE_VAX750"
	Vax730 SubCpuType = "CPU_SUBTYPE_VAX730"
	UvAxI SubCpuType = "CPU_SUBTYPE_UVAXI"
	UvAxII SubCpuType = "CPU_SUBTYPE_UVAXII"
	Vax8200 SubCpuType = "CPU_SUBTYPE_VAX8200"
	Vax8500 SubCpuType = "CPU_SUBTYPE_VAX8500"
	Vax8600 SubCpuType = "CPU_SUBTYPE_VAX8600"
	Vax8650 SubCpuType = "CPU_SUBTYPE_VAX8650"
	Vax8800 SubCpuType =  "CPU_SUBTYPE_VAX8800"
	UvaxIII SubCpuType = "CPU_SUBTYPE_UVAXIII"

)

var validBitsValues = map[Bits]bool {
	Bits32: true,
	Bits64: true,
}

var validEndiannessValues = map[Endianness]bool {
	BigEndian: true,
	LittleEndian: true,
}

var validStatusValues = map[Status]bool {
	Secure: true,
	Insecure: true,
	Info: true,
	Warning: true,
}

var validCpuValues = map[CpuType]bool{
	VAX: true,
	MC680X0: true,
 	I386: true,
	X8664: true,
 	MIPS: true,
 	MC98000: true,
 	HPPA: true,
 	ARM: true,
 	ARM64: true,
 	MC88000: true,
 	SPARC: true,
 	I860: true,
 	Alpha: true,
 	PowerPC: true,
	PowerPC64: true,
}

var validSubCpuValues = map[CpuType]map[SubCpuType]bool{
	VAX: {
		VaxAll: true,
		Vax780: true,
		Vax785: true,
		Vax750: true,
		Vax730: true,
		UvAxI: true,
		UvAxII: true,
		Vax8200: true,
		Vax8500: true,
		Vax8600: true,
		Vax8650: true,
		Vax8800: true,
		UvaxIII: true,
	},
	MC680X0: {
		Mc880000All: true,
		MC88100: true,
		MC88110: true,
	},
	I386: {
		IntelModelAll: true,
		IntelHTT: true,
		I386All: true,
		I486: true,
		I586: true,
		Pentium3: true,
		PentiumM: true,
		Pentium4: true,
		Itanium: true,
		Xeon: true,
		XeonMP: true,
		Pentium4M: true,
		Itanium2: true,
		PentiumPro: true,
		Pentium3M: true,
		Pentium3Xeon: true,
		PentiiM3: true,
		I486Sx: true,
		PentiiM5: true,
		Celeron: true,
		CeleronMobile: true,
	},
	X8664: {
		X8664All: true,
		X86Arch1: true,
	},
	MIPS: {
		MipsAll: true,
		MipsR2300: true,
		MipsR2600: true,
		MipsR2800: true,
		MipsR2000a: true,
		MipsR2000: true,
		MipsR3000a: true,
		MipsR3000: true,
	},
	MC98000: {
		MC98000All: true,
		MC98601: true,
	},
	HPPA: {
		Hppa7100: true,
		Hppa7100LC: true,

	},
	ARM: {
		ArmAll12: true,
		ArmV4T: true,
		ArmV6: true,
		ArmV5TEJ: true,
		ArmXScale: true,
		ArmV7: true,
		ArmV7F: true,
		ArmV7S: true,
		ArmV7K: true,
		ArmV6M: true,
		ArmV7M: true,
		ArmV7EM : true,
	},
	ARM64: {
		ArmAll12: true,
		ArmV4T: true,
		ArmV6: true,
		ArmV5TEJ: true,
		ArmXScale: true,
		ArmV7: true,
		ArmV7F: true,
		ArmV7S: true,
		ArmV7K: true,
		ArmV6M: true,
		ArmV7M: true,
		ArmV7EM : true,
	},
	MC88000: {
		MC680X0All: true,
		MC68040: true,
		MC68030Only: true,
	},
	SPARC: {
		SparcAll: true,
	},
	I860: {
		I860All: true,
		I860860: true,
	},
	Alpha: {
		AlphaAll: true,
	},
	PowerPC: {
		PowerPCAll: true,
		PowerPC601: true,
		PowerPC602: true,
		PowerPC603: true,
		PowerPC603e: true,
		PowerPC603ev: true,
		PowerPC604: true,
		PowerPC604e: true,
		PowerPC620: true,
		PowerPC750: true,
		PowerPC7400: true,
		PowerPC7450: true,
		PowerPC970: true,
	},
	PowerPC64: {
		PowerPCAll: true,
		PowerPC601: true,
		PowerPC602: true,
		PowerPC603: true,
		PowerPC603e: true,
		PowerPC603ev: true,
		PowerPC604: true,
		PowerPC604e: true,
		PowerPC620: true,
		PowerPC750: true,
		PowerPC7400: true,
		PowerPC7450: true,
		PowerPC970: true,
	},
}

func bitsValidator(fl validator.FieldLevel) bool {
	return validBitsValues[Bits(fl.Field().Uint())]
}

func endiannessValidator(fl validator.FieldLevel) bool {
	return validEndiannessValues[Endianness(fl.Field().String())]
}

func statusValidator(fl validator.FieldLevel) bool {
	return validStatusValues[Status(fl.Field().String())]
}

func cpuValidator(fl validator.FieldLevel) bool {
	return validCpuValues[CpuType(fl.Field().String())]
}

func subCpuValidator(fl validator.FieldLevel) bool {
	return validSubCpuValues[fl.Parent().Interface().(MachoInfo).Cpu][SubCpuType(fl.Field().String())]
}


func (e *MachoInfo) FromMap(m map[string]interface{}) Entity {
	if v, ok := m["bits"]; ok {
		e.Bits = Bits(v.(uint))
	}
	if v, ok := m["endianness"]; ok {
		e.Endianness = Endianness(v.(string))
	}
	if v, ok := m["cpu"]; ok {
		e.Cpu = CpuType(v.(string))
	}
	if v, ok := m["sub_cpu"]; ok {
		e.SubCpu = SubCpuType(v.(string))
	}
	return e
}

func (e *MachoInfo) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"bits": uint(e.Bits),
		"endianess": string(e.Endianness),
		"cpu": string(e.Cpu),
		"sub_cpu": string(e.SubCpu),
	}
}

func (e *MachoInfo) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *BinaryAnalysisResult) FromMap(m map[string]interface{}) Entity {
	if v, ok := m["issue"]; ok {
		e.Issue = v.(string)
	}
	if v, ok := m["description"]; ok {
		e.Description = v.(string)
	}
	if v, ok := m["status"]; ok {
		e.Status = Status(v.(string))
	}
	if v, ok := m["cvss"]; ok {
		e.Cvss = v.(float32)
	}
	if v, ok := m["cwe"]; ok {
		e.CWE = CWE(v.(string))
	}
	return e
}

func (e *BinaryAnalysisResult) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"issue": e.Issue,
		"description": e.Description,
		"status": string(e.Status),
		"cvss": e.Cvss,
		"cwe": string(e.CWE),
	}
}

func (e *BinaryAnalysisResult) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *BinaryAnalysis) FromMap(m map[string]interface{}) Entity {
	if v, ok := m["libraries"]; ok {
		e.Libraries = v.([]string)
	}
	if v, ok := m["macho"]; ok {
		macho := &MachoInfo{}
		e.Macho = *(macho.FromMap(v.(map[string]interface{})).(*MachoInfo))
	}
	if v, ok := m["results"]; ok {
		e.Results = []BinaryAnalysisResult{}
		for _, r := range v.([]map[string]interface{}) {
			result := &BinaryAnalysisResult{}
			e.Results = append(e.Results, *(result.FromMap(r).(*BinaryAnalysisResult)))
		}
	}
	return e
}

func (e *BinaryAnalysis) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"libraries": e.Libraries,
		"macho": e.Macho.ToMap(),
		"results": []map[string]interface{}{},
	}
	for _, r := range e.Results {
		m["results"] = append(m["results"].([]map[string]interface{}), r.ToMap())
	}
	return m
}

func (e *BinaryAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}
