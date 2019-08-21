package binary

import (
	"debug/macho"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)


// Analyzes the macho headers to extract the cpu information. We use the standard macho library with some
// maps to extract the data.
func GetMachoInfo(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	file, err := macho.Open(command.Path)
	if err != nil {
		return entity, err
	}
	header := file.FileHeader
	switch header.Magic {
	case Magic32:
		entity.Macho.Bits = entities.Bits32
		entity.Macho.Endianness = entities.BigEndian
	case Magic64:
		entity.Macho.Bits = entities.Bits64
		entity.Macho.Endianness = entities.BigEndian
	case Cigam32:
		entity.Macho.Bits = entities.Bits32
		entity.Macho.Endianness = entities.LittleEndian
	case Cigam64:
		entity.Macho.Bits = entities.Bits64
		entity.Macho.Endianness = entities.LittleEndian
	default:
		return entity, fmt.Errorf("magic number %#x not recognized", header.Magic)
	}
	if cpu, ok := cpuTypes[header.Cpu]; ok {
		entity.Macho.Cpu = entities.CpuType(cpu)
		switch entity.Macho.Cpu {
		case entities.I386:
			if subCpu, ok := intelSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.X8664:
			if subCpu, ok := intel64Subtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.MIPS:
			if subCpu, ok := mipsSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.MC680X0:
			if subCpu, ok := mc680Subtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.MC98000:
			if subCpu, ok := mc98000Subtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.HPPA:
			if subCpu, ok := hppaSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.ARM, entities.ARM64:
			if subCpu, ok := armSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.VAX:
			if subCpu, ok := vaxSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.MC88000:
			if subCpu, ok := mc88Subtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.SPARC:
			if subCpu, ok := sparcSutype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.I860:
			if subCpu, ok := i860Subtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		case entities.PowerPC, entities.PowerPC64:
			if subCpu, ok := powerPcSubtype[header.SubCpu]; ok {
				entity.Macho.SubCpu = entities.SubCpuType(subCpu)
			}
		}
	} else {
		return entity, fmt.Errorf("invalid cpu %d number", header.Cpu)
	}
	return entity, nil
}
