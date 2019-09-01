package input

import (
	"flag"
	"fmt"
	"github.com/kardianos/osext"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/adapters/services"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stevenroose/gonfig"
	"os"
	"path/filepath"
	"strings"
)

// LoadConfiguration loads the Configuration file in three locations:
// - The path provided by the user, if any.
// - The current working directory
// - The binary path (the path where the executable is right now)
// If the file is not found in the first path, or if it's found but there is some error loading it, the function
// tries the next location in the list. If everything fails, the default Configuration would be used.
// As we really don't care about where we get the Configuration, it doesn't make a lot of sense to return an error, so
// the function just returns a string to tell the user what happened
func ConfigurationAdapter(command entities.Command, entity *entities.Command, adapter *adapters.AdapterMap) {
	configuration := entities.Configuration{
		Analysis:           []string{"binary", "code", "plist", "lookup", "files"},
		JSONFormat:         false,
		DefaultCountry:     "us",
		ToolsFolder:        getToolsFolder(),
		PerformDomainCheck: false,
	}
	_ = adapter.Output.Error(output.ParseError(command, "", extractConfigurationFile(getPaths(command), &configuration, adapter)))
	loadConfiguration(&configuration, entity, adapter)
}

// Returns the folder where the program external binary tools (jtool, class-dump) is present. By default, depending on
// the environment where the program is executing (testing/not testing) the tools will be in vulnscan/tools/tools
// (testing) or in a sibling folder of the vulnscan binary. The function also looks for a folder configured using the
// configuration file.
func getToolsFolder() string {
	var parentFolder string
	if flag.Lookup("test.v") == nil {
		parentFolder, _ = osext.ExecutableFolder()
	} else {
		parentFolder, _ = test.FindMainFolder()
	}
	return parentFolder + string(os.PathSeparator) + "tools" + string(os.PathSeparator)
}

func getPaths(command entities.Command) []string {
	var paths []string
	// First, we try the provided path, if it is not empty
	if command.Path != "" {
		paths = append(paths, command.Path)
	}
	// Next we check the current execution path
	var currentDir string
	if flag.Lookup("test.v") == nil {
		// Not testing
		currentDir, _ = os.Getwd()
	} else {
		currentDir, _ = test.FindMainFolder()
	}
	for _, ex := range []string{".toml", ".yaml", ".json"} {
		paths = append(paths, filepath.Join(currentDir, "vulnscan" + ex))
	}
	// Finally, we check the folder where the vulnscan binary is located
	if binaryPath, err := osext.ExecutableFolder(); err == nil {
		for _, ex := range []string{".toml", ".yaml", ".json"} {
			paths = append(paths, filepath.Join(binaryPath, "vulnscan" + ex))
		}
	}
	return paths
}

func extractConfigurationFile(paths []string, configuration *entities.Configuration, adapter *adapters.AdapterMap) error {
	var d gonfig.FileDecoderFn
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			continue
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json":
			d = gonfig.DecoderJSON
		case ".yaml":
			d = gonfig.DecoderYAML
		case ".toml":
			d = gonfig.DecoderTOML
		default:
			return fmt.Errorf(
				"%s is not a valid extension for the configuration file. Only json, yaml and toml are allowed",
				strings.ToLower(filepath.Ext(p)))
		}
		_ = adapter.Output.Logger(output.ParseInfo(entities.Command{}, "", fmt.Sprintf("Configuration file found at %s, loading...", p)))
		// Now we have a valid path and a valid extension, we can return the error
		return gonfig.Load(configuration, gonfig.Conf{
			FileDefaultFilename: p,
			FileDecoder:         d,
			FlagDisable:         true, // does not work, so we have to do it manually
			EnvPrefix:           "VULNSCAN_",
		})
	}
	return fmt.Errorf("configuration file not found on %s", strings.Join(paths, ", "))
}

func loadConfiguration(configuration *entities.Configuration, command *entities.Command, adapter *adapters.AdapterMap) {
	// Command configuration
	if len(configuration.BinaryPath) > 0 {
		command.Path = configuration.BinaryPath
	} else if len(configuration.SourcePath) > 0 {
		command.Path = configuration.SourcePath
		command.Source = true
	}
	if len(configuration.ToolsFolder) > 0 {

	}
	command.Analysis = map[entities.AnalysisCheck]bool{}
	for _, a := range configuration.Analysis {
		command.Analysis[entities.AnalysisCheck(a)] = true
	}
	command.Country = configuration.DefaultCountry


	// Adapter configuration
	if configuration.JSONFormat {
		adapter.Output.Result = output.JsonAdapter
	}
	if configuration.PerformDomainCheck {
		adapter.Services.MalwareDomains = services.MalwareDomainsAdapter
	}
	if len(configuration.VirusScanKey) > 0 {
		command.VirusTotalKey = configuration.VirusScanKey
		adapter.Services.VirusScan = services.VirusTotalAdapter
	}
}

