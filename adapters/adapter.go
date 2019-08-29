package adapters

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

type (
	// Due to the lack of generics in Go 1, we have to do this (or enter a type casting hell).
	// Looking forward to Go 2
	GenericAdapter func(utils.Command, entities.Entity) error
	ToolAdapter    func(utils.Command, *entities.BinaryAnalysis) error
	MalwareAdapter func(utils.Command, *entities.CodeAnalysis) error
	VirusAdapter   func(utils.Command, *entities.VirusAnalysis) error
	ErrorAdapter   func(utils.Command, *entities.Error) error
	LogAdapter     func(utils.Command, *entities.LogMessage) error

	ServiceAdapters struct {
		MalwareDomains MalwareAdapter
		VirusScan      VirusAdapter
	}

	ToolAdapters struct {
		ClassDump ToolAdapter
		Libs      ToolAdapter
		Headers   ToolAdapter
		Symbols   ToolAdapter
	}

	OutputAdapters struct {
		Logger LogAdapter
		Result GenericAdapter
		Error  ErrorAdapter
	}

	AdapterMap struct {
		Services ServiceAdapters
		Tools    ToolAdapters
		Output   OutputAdapters
	}
)
