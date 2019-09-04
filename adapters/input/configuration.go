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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var configurationToCommandAnalysisMap = map[string]entities.AnalysisCheck {
	"binary": entities.DoBinary,
	"code": entities.DoCode,
	"store": entities.DoStore,
	"files": entities.DoFiles,
	"plist": entities.DoPList,
}


// LoadConfiguration loads the Configuration file in three locations:
// - The path provided by the user, if any.
// - The current working directory
// - The binary path (the path where the executable is right now)
// If the file is not found in the first path, or if it's found but there is some error loading it, the function
// tries the next location in the list. If everything fails, the default Configuration would be used.
// As we really don't care about where we get the Configuration, it doesn't make a lot of sense to return an error, so
// the function just returns a string to tell the user what happened
func ConfigurationAdapter(command entities.Command, entity *entities.Command, adapter *adapters.AdapterMap) {
	var configuration = entities.Configuration{}
	if err := extractConfigurationFile(command, &configuration, adapter); err != nil {
		_ = adapter.Output.Logger(output.ParseWarning(command, "", "configuration file not found, using default configuration"))
	} else {
		loadConfiguration(command, &configuration, entity, adapter)
	}
	loadDefaultCommand(entity)
}

// Returns the folder where the program external binary tools (jtool, class-dump) is present. By default, the tools will
// be in a sibling folder of the vulnscan binary (or main folder if testing). The function also looks for a folder configured using the
// configuration file.
func getToolsFolder() string {
	var folder string
	if flag.Lookup("test.v") == nil {
		parentFolder, _ := osext.ExecutableFolder()
		folder = filepath.Join(parentFolder, "tools")
	} else {
		folder, _ = test.FindTools()
	}
	return folder
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

func extractConfigurationFile(command entities.Command, configuration *entities.Configuration, adapter *adapters.AdapterMap) error {
	var (
		paths = getPaths(command)
		d gonfig.FileDecoderFn
	)
	_ = adapter.Output.Logger(output.ParseInfo(command, "", "searching for configuration files on %s", strings.Join(paths, ", ")))
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configuration file found on %s", p))
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
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "Configuration file found at %s, loading...", p))
		// Now we have a valid path and a valid extension, we can return the error
		s, _ := ioutil.ReadFile(p)
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "File content: %s", s))
		return gonfig.Load(configuration, gonfig.Conf{
			FileDefaultFilename: p,
			FileDecoder:         d,
			FlagDisable:         true, // does not work, so we have to do it manually
			EnvPrefix:           "VULNSCAN_",
		})
	}
	return fmt.Errorf("configuration file not found")
}

func loadConfiguration(command entities.Command, configuration *entities.Configuration, entity *entities.Command, adapter *adapters.AdapterMap) {
	_ = adapter.Output.Logger(output.ParseInfo(command, "", "loading configuration"))

	// Command configuration
	if len(configuration.BinaryPath) > 0 {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured binary path: %s", configuration.BinaryPath))
		entity.Path = configuration.BinaryPath
	} else if len(configuration.SourcePath) > 0 {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured source path: %s", configuration.SourcePath))
		entity.Path = configuration.SourcePath
		entity.Source = true
	} else {
		_ = adapter.Output.Logger(output.ParseWarning(command, "", "no path found in configuration file"))
	}
	if len(configuration.ToolsFolder) > 0 {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured tools folder: %s", configuration.ToolsFolder))
		entity.Tools = configuration.ToolsFolder
	} else {
		_ = adapter.Output.Logger(output.ParseWarning(command, "", "no tools path in configuration file"))
	}
	entity.Analysis = map[entities.AnalysisCheck]bool{}
	if len(configuration.Analysis) == 0 {
		_ = adapter.Output.Logger(output.ParseWarning(command, "", "no analysis set in configuration file"))
	} else {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured analysis: %v", configuration.Analysis))
	}
	for _, a := range configuration.Analysis {
		if v, ok := configurationToCommandAnalysisMap[a]; ok {
			entity.Analysis[v] = true
		} else {
			_ = adapter.Output.Logger(output.ParseWarning(
				entities.Command{}, "", "invalid analysis name found in configuration file: %s, skipping", a))
		}

	}
	if country := configuration.DefaultCountry; len(country) != 2 && len(country) != 0 {
		_ = adapter.Output.Logger(output.ParseWarning(
			entities.Command{}, "", "invalid country code in configuration file: %s, using default", country))
	} else {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured country for store search: %s", country))
		entity.Country = country
	}
	if configuration.SilentMode {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured silent mode"))
		entity.Silent = true
	}

	// Adapter configuration
	if configuration.JSONFormat {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured outupt: json"))
		adapter.Output.Result = output.JsonAdapter
	} else {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured outupt: console"))
	}
	if configuration.PerformDomainCheck {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured malware domains check: activated"))
		adapter.Services.MalwareDomains = services.MalwareDomainsAdapter
	} else {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured malware domains check: deactivated"))
	}
	if len(configuration.VirusScanKey) > 0 {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured virus total analysis: activated"))
		entity.VirusTotalKey = configuration.VirusScanKey
		adapter.Services.VirusScan = services.VirusTotalAdapter
	} else {
		_ = adapter.Output.Logger(output.ParseInfo(command, "", "configured virus total analysis: deactivated"))
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, "", "configuration loaded"))
}

func loadDefaultCommand(entity *entities.Command) {
	if len(entity.Analysis) == 0 {
		entity.Analysis = map[entities.AnalysisCheck]bool{
			entities.DoPList: true,
			entities.DoBinary: true,
			entities.DoFiles: true,
			entities.DoStore: true,
			entities.DoCode: true,
		}
	}
	if len(entity.Country) == 0 {
		entity.Country = "us"
	}
	if len(entity.Tools) == 0 {
		entity.Tools = getToolsFolder()
	}
}
