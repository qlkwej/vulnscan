package entities


type Configuration struct {

	// Command flags

	// Path where the source to analyze is present in the filesystem.
	SourcePath string `id:"source" desc:"Path to the source code to analyze"`
	// Path where the binary to analyze is present in the filesystem.
	BinaryPath string `id:"binary" desc:"Path to the binary .ipa file to analyze"`
	// Folder where the external binary tools (jtool, etc.) are in the system. If nothing is passed, the application
	// expects them to be in a sibling folder relative to the app binary.
	ToolsFolder string `id:"tools" desc:"Folder where the program external binaries are located"`

	// String slice with the scans to make when calling scan command
	Analysis []string `id:"scans" desc:"Test to do when calling scan command"`
	// Default country to pass to the lookup in the app store command.
	DefaultCountry string `id:"country" desc:"Country to use in the apple store lookup"`


	// Adapters flags

	// Virus scan key. If included, the app will call virus scan api to scan the code
	// TODO: change to a boolean flag when we have the collective key
	VirusScanKey string `id:"virus" desc:"Virus Scan API key to use the service"`
	// Whether or not we output in json. Defaults to false
	JSONFormat bool `id:"json" desc:"Activate the json output"`
	// Whether or not we look for malware domains in malwaredomainlist.com. Defaults to false.
	PerformDomainCheck bool `id:"domains" desc:"Activate domain check from www.malwaredomainlist.com"`
	// Activate silent mode
	SilentMode bool `id:"silent" desc:"Deactivate info messages logging"`
}



