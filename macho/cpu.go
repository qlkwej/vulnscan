package macho

import "debug/macho"

const arch64 macho.Cpu = 0x1000000

type (
	cpuTypesMap map[macho.Cpu]string
	cpuSubTypesMap map[uint32]string
)

var (
	cpuTypes = cpuTypesMap {
		1:                    "VAX",
		6:                    "MC680x0",
		7:                    "i386",
		arch64 | 7:           "x86_64",
		8:                    "MIPS",
		10:                   "MC98000",
		11:                   "HPPA",
		12:                   "ARM",
		arch64 | 12: 		  "ARM64",
		13:                   "MC88000",
		14:                   "SPARC",
		15:                   "i860",
		16:                   "Alpha",
		18:                   "PowerPC",
		arch64 | 18: 		  "PowerPC64",
	}

	intelSubtype = cpuSubTypesMap{
		0:   "CPU_SUBTYPE_INTEL_MODEL_ALL",
		1:   "CPU_THREADTYPE_INTEL_HTT",
		3:   "CPU_SUBTYPE_I386_ALL",
		4:   "CPU_SUBTYPE_486",
		5:   "CPU_SUBTYPE_586",
		8:   "CPU_SUBTYPE_PENTIUM_3",
		9:   "CPU_SUBTYPE_PENTIUM_M",
		10:  "CPU_SUBTYPE_PENTIUM_4",
		11:  "CPU_SUBTYPE_ITANIUM",
		12:  "CPU_SUBTYPE_XEON",
		34:  "CPU_SUBTYPE_XEON_MP",
		42:  "CPU_SUBTYPE_PENTIUM_4_M",
		43:  "CPU_SUBTYPE_ITANIUM_2",
		38:  "CPU_SUBTYPE_PENTPRO",
		40:  "CPU_SUBTYPE_PENTIUM_3_M",
		52:  "CPU_SUBTYPE_PENTIUM_3_XEON",
		102: "CPU_SUBTYPE_PENTII_M3",
		132: "CPU_SUBTYPE_486SX",
		166: "CPU_SUBTYPE_PENTII_M5",
		199: "CPU_SUBTYPE_CELERON",
		231: "CPU_SUBTYPE_CELERON_MOBILE",
	}

	intel64Subtype = cpuSubTypesMap{
		3: "CPU_SUBTYPE_X86_64_ALL",
		4: "CPU_SUBTYPE_X86_ARCH1",
	}

	mipsSubtype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_MIPS_ALL",
		1: "CPU_SUBTYPE_MIPS_R2300",
		2: "CPU_SUBTYPE_MIPS_R2600",
		3: "CPU_SUBTYPE_MIPS_R2800",
		4: "CPU_SUBTYPE_MIPS_R2000a",
		5: "CPU_SUBTYPE_MIPS_R2000",
		6: "CPU_SUBTYPE_MIPS_R3000a",
		7: "CPU_SUBTYPE_MIPS_R3000",
	}

	mc680Subtype = cpuSubTypesMap{
		1: "CPU_SUBTYPE_MC680x0_ALL",
		2: "CPU_SUBTYPE_MC68040",
		3: "CPU_SUBTYPE_MC68030_ONLY",
	}

	mc98000Subtype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_MC98000_ALL",
		1: "CPU_SUBTYPE_MC98601",
	}

	hppaSubtype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_HPPA_7100",
		1: "CPU_SUBTYPE_HPPA_7100LC",
	}

	mc88Subtype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_MC88000_ALL",
		1: "CPU_SUBTYPE_MC88100",
		2: "CPU_SUBTYPE_MC88110",
	}

	sparcSutype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_SPARC_ALL",
	}

	i860Subtype = cpuSubTypesMap{
		0: "CPU_SUBTYPE_I860_ALL",
		1: "CPU_SUBTYPE_I860_860",
	}

	powerPcSubtype = cpuSubTypesMap{
		0:   "CPU_SUBTYPE_POWERPC_ALL",
		1:   "CPU_SUBTYPE_POWERPC_601",
		2:   "CPU_SUBTYPE_POWERPC_602",
		3:   "CPU_SUBTYPE_POWERPC_603",
		4:   "CPU_SUBTYPE_POWERPC_603e",
		5:   "CPU_SUBTYPE_POWERPC_603ev",
		6:   "CPU_SUBTYPE_POWERPC_604",
		7:   "CPU_SUBTYPE_POWERPC_604e",
		8:   "CPU_SUBTYPE_POWERPC_620",
		9:   "CPU_SUBTYPE_POWERPC_750",
		10:  "CPU_SUBTYPE_POWERPC_7400",
		11:  "CPU_SUBTYPE_POWERPC_7450",
		100: "CPU_SUBTYPE_POWERPC_970",
	}

	armSubtype = cpuSubTypesMap{
		0:  "CPU_SUBTYPE_ARM_ALL12",
		5:  "CPU_SUBTYPE_ARM_V4T",
		6:  "CPU_SUBTYPE_ARM_V6",
		7:  "CPU_SUBTYPE_ARM_V5TEJ",
		8:  "CPU_SUBTYPE_ARM_XSCALE",
		9:  "CPU_SUBTYPE_ARM_V7",
		10: "CPU_SUBTYPE_ARM_V7F",
		11: "CPU_SUBTYPE_ARM_V7S",
		12: "CPU_SUBTYPE_ARM_V7K",
		14: "CPU_SUBTYPE_ARM_V6M",
		15: "CPU_SUBTYPE_ARM_V7M",
		16: "CPU_SUBTYPE_ARM_V7EM",
	}

	vaxSubtype = cpuSubTypesMap{
		0:  "CPU_SUBTYPE_VAX_ALL",
		1:  "CPU_SUBTYPE_VAX780",
		2:  "CPU_SUBTYPE_VAX785",
		3:  "CPU_SUBTYPE_VAX750",
		4:  "CPU_SUBTYPE_VAX730",
		5:  "CPU_SUBTYPE_UVAXI",
		6:  "CPU_SUBTYPE_UVAXII",
		7:  "CPU_SUBTYPE_VAX8200",
		8:  "CPU_SUBTYPE_VAX8500",
		9:  "CPU_SUBTYPE_VAX8600",
		10: "CPU_SUBTYPE_VAX8650",
		11: "CPU_SUBTYPE_VAX8800",
		12: "CPU_SUBTYPE_UVAXIII",
	}
)
