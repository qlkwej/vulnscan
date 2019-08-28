package mocks

import "github.com/simplycubed/vulnscan/adapters"

func GetTestMap(mockOutputAdapter adapters.GenericAdapter) adapters.AdapterMap {
	return adapters.AdapterMap{
		Tools: adapters.ToolAdapters{
			ClassDump: MockClassDumpAdapter,
			Libs:      LibsAdapter,
			Headers:   HeadersAdapter,
			Symbols:   SymbolsAdapter,
		},
		Services: adapters.ServiceAdapters{
			MalwareDomains: MalwareDomainsAdapter,
			VirusScan:      VirusTotalAdapter,
		},
		Output: adapters.OutputAdapters{
			Logger: LogAdapter,
			Result: mockOutputAdapter,
			Error:  ErrorAdapter,
		},
	}
}
