package macho

import (
	"debug/macho"
	"fmt"
)

const (
	// Magic32 is the Mach-O 32-bit magic number in big-endian
	Magic32 uint32 = 0xFEEDFACE
	// Cigam32 is the Mach-O 32-bit magic number in little-endian
	Cigam32 uint32 = 0xCEFAEDFE
	// Magic64 is the Mach-O 64-bit magic number in big-endian
	Magic64 uint32 = 0xFEEDFACF
	// Cigam64 is the 64-bit magic number in little-endian
	Cigam64 uint32 = 0xCFFAEDFE
)

// Analyzes the macho headers to extract the cpu information. We use the standard macho library with some
// maps to extract the data.
func GetMachoInfo(path string) (map[string]string, error) {
	info := map[string]string{}
	file, err := macho.Open(path)
	if err != nil {
		return info, err
	}
	header := file.FileHeader
	switch header.Magic {
	case Magic32:
		info["bits"] = "32bits"
		info["endianness"] = "big_endian"
	case Magic64:
		info["bits"] = "64bits"
		info["endianness"] = "big_endian"
	case Cigam32:
		info["bits"] = "32bits"
		info["endianness"] = "little_endian"
	case Cigam64:
		info["bits"] = "64bits"
		info["endianness"] = "little_endian"
	default:
		return info, fmt.Errorf("magic number %#x not recognized", header.Magic)
	}
	if cpu, ok := cpuTypes[header.Cpu]; ok {
		info["cpu_type"] = cpu
		switch cpu {
		case "i386":
			if subCpu, ok := intelSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "x86_64":
			if subCpu, ok := intel64Subtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "MIPS":
			if subCpu, ok := mipsSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "MC680x0":
			if subCpu, ok := mc680Subtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "MC98000":
			if subCpu, ok := mc98000Subtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "HPPA":
			if subCpu, ok := hppaSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "ARM", "ARM64":
			if subCpu, ok := armSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "VAX":
			if subCpu, ok := vaxSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "MC88000":
			if subCpu, ok := mc88Subtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "SPARC":
			if subCpu, ok := sparcSutype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "i860":
			if subCpu, ok := i860Subtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		case "PowerPC", "PowerPC64":
			if subCpu, ok := powerPcSubtype[header.SubCpu]; ok {
				info["sub_cpu_type"] = subCpu
			} else {
				info["sub_cpu_type"] = "UNRECOGNIZED"
			}
		}
	} else {
		return info, fmt.Errorf("invalid cpu %d number", header.Cpu)
	}
	return info, nil
}