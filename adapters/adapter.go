package adapters

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

type (
	Adapter func(command utils.Command, entity entities.Entity) error

	ServiceAdapters struct {
		MalwareDomains 	Adapter
		VirusScan 		Adapter
	}

	ToolAdapters struct {
		ClassDump 	Adapter
		Libs 		Adapter
		Headers 	Adapter
		Symbols 	Adapter
	}

	OutputAdapters struct {
		Logger Adapter
		Result Adapter
		Error Adapter
	}

	AdapterMap struct {
		Services ServiceAdapters
		Tools    ToolAdapters
		Output   OutputAdapters
	}
)

