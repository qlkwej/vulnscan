package utils

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kardianos/osext"
	"github.com/stevenroose/gonfig"
)

// Configuration object
var Configuration = struct {
	// String slice with the scans to make when calling scan command
	Scans []string `id:"scans" desc:"Test to do when calling scan command"`
	// Whether or not we output in json. Defaults to false
	JSONFormat bool `id:"json" desc:"Activate the json output"`
	// Whether or not we output colored logs. Defaults to true.
	ColoredLog bool `id:"colored" desc:"Do colored output"`
	// Path where the source to analyze is present in the filesystem.
	SourcePath string `id:"source" desc:"Path to the source code to analyze"`
	// Path where the binary to analyze is present in the filesystem.
	BinaryPath string `id:"binary" desc:"Path to the binary .ipa file to analyze"`
	// Virus scan key. If included, the app will call virus scan api to scan the code
	// TODO: change to a boolean flag when we have the collective key
	VirusScanKey string `id:"virus" desc:"Virus Scan API key to use the service"`
	// Default country to pass to the lookup in the app store command.
	DefaultCountry string `id:"country" desc:"Country to use in the apple store lookup"`
	// Folder where the external binary tools (jtool, etc.) are in the system. If nothing is passed, the application
	// expects them to be in a sibling folder relative to the app binary.
	ToolsFolder string `id:"tools" desc:"Folder where the program external binaries are located"`
	// Whether or not we look for malware domains in malwaredomainlist.com. Defaults to false.
	PerformDomainCheck bool `id:"domains" desc:"Activate domain check from www.malwaredomainlist.com"`
}{
	Scans:              []string{"binary", "code", "plist", "lookup", "files"},
	JSONFormat:         false,
	SourcePath:         "",
	BinaryPath:         "",
	VirusScanKey:       "",
	DefaultCountry:     "us",
	ToolsFolder:        "",
	PerformDomainCheck: false,
	ColoredLog:         true,
}

// Loads the configuration file and checks that:
// - The activated scan names are all valid
// - The source/binary paths exists
func loadConfigurationFile(path string, decoder gonfig.FileDecoderFn) error {
	if err := gonfig.Load(&Configuration, gonfig.Conf{
		FileDefaultFilename: path,
		FileDecoder:         decoder,
		FlagDisable:         true, // does not work, so we have to do it manually
		EnvPrefix:           "VULNSCAN_",
	}); err != nil {
		return err
	}
	if err := CheckConfigurationScans(Configuration.Scans); err != nil {
		ResetConfiguration()
		return err
	}
	for _, p := range []*string{&Configuration.BinaryPath, &Configuration.SourcePath} {
		*p, _ = filepath.Abs(*p)
		if _, err := os.Stat(*p); os.IsNotExist(err) {
			ResetConfiguration()
			return err
		}
	}
	return nil
}

// Checks that the scans in the array are valid names, case insensitive, and that there is not repetition
// in the list. This is crucial, because we use it to measure the goroutines loop, so if a repeated scan
// name is included, the application may hang forever (or we would need to pass a context with a timeout)
func CheckConfigurationScans(scans []string) error {
	plist, store := false, false
	pattern := "binary|code|plist|lookup|files"
	for _, scan := range scans {
		m, _ := regexp.MatchString(pattern, strings.ToLower(scan))
		if !m {
			return fmt.Errorf("invalid scan name %s", scan)
		}
		if scan == "plist" {
			plist = true
		} else if scan == "lookup" {
			store = true
		}
		// Remove the matched pattern so we don't match repeated keys.
		pattern = strings.Replace(pattern, scan+"|", "", 1)
		pattern = strings.Replace(pattern, "|"+scan, "", 1)
		pattern = strings.Replace(pattern, scan, "", 1)
		// If we complete the list, replace the pattern with something that can't match
		if len(pattern) == 0 {
			pattern = "$^"
		}
		if store && !plist {
			// We cannot run store lookup scan without plist scan
			return fmt.Errorf("invalid scan combination: lookup scan depends on plist scan")
		}
	}
	return nil
}

// Resets the configuration to the original one
func ResetConfiguration() {
	if e := gonfig.LoadMap(&Configuration, map[string]interface{}{
		"scans":   []string{"binary", "code", "plist", "lookup"},
		"json":    false,
		"source":  "",
		"binary":  "",
		"virus":   "",
		"country": "us",
		"tools":   "",
		"domains": false,
	}, gonfig.Conf{}); e != nil {
		panic("FATAL ERROR resetting configuration file")
	}
}

// LoadConfiguration loads the Configuration file in three locations:
// - The path provided by the user, if any.
// - The current working directory
// - The binary path (the path where the executable is right now)
// If the file is not found in the first path, or if it's found but there is some error loading it, the function
// tries the next location in the list. If everything fails, the default Configuration would be used.
// As we really don't care about where we get the Configuration, it doesn't make a lot of sense to return an error, so
// the function just returns a string to tell the user what happened
func LoadConfiguration(path string) string {
	// We use returnString to build the returned message. As we
	var sb strings.Builder
	// First, we try the provided path, if it is not empty
	if path != "" {
		// As we need to exit and continue if the extension of the file is not one of the supported ones, we encapsulate
		// the checks in a function (similar effect to a do {} while false in C++).
		if err := func() error {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return err
			}
			// We check the format of the Configuration file to load the decoder
			var decoder gonfig.FileDecoderFn
			if ext := strings.ToLower(filepath.Ext(path)); ext == ".toml" {
				decoder = gonfig.DecoderTOML
			} else if ext == ".json" {
				decoder = gonfig.DecoderJSON
			} else if ext == ".yaml" {
				decoder = gonfig.DecoderYAML
			} else {
				return fmt.Errorf("configuration file %s doesn't have one of the required formats (TOML, YAML, JSON)", path)
			}
			if err := loadConfigurationFile(path, decoder); err != nil {
				return fmt.Errorf("error loading the Configuration file found in %s: %s", path, err)
			}
			// If we get here, we have loaded the Configuration file successfully...
			return nil
		}(); err == nil {
			// ... so we return a success string
			return fmt.Sprintf("Configuration file loaded from %s", path)
			// In any other case, we pass the error to the returning string and keep searching in other locations.
		} else if os.IsNotExist(err) {
			sb.WriteString(fmt.Sprintf("Configuration file not found in %s", path))
		} else {
			sb.WriteString(err.Error())
		}
	}
	// Next we check the current execution path
	if err := func() error {
		var currentDir string
		if flag.Lookup("test.v") == nil {
			// Not testing
			currentDir, _ = os.Getwd()
		} else {
			currentDir, _ = FindMainFolder()
		}
		for p, d := range map[string]gonfig.FileDecoderFn{
			filepath.Join(currentDir, "vulnscan.toml"): gonfig.DecoderTOML,
			filepath.Join(currentDir, "vulnscan.yaml"): gonfig.DecoderYAML,
			filepath.Join(currentDir, "vulnscan.json"): gonfig.DecoderJSON,
		} {
			// If the file exist, we try to load the Configuration
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				if err := loadConfigurationFile(p, d); err == nil {
					// If we succeed, we can return a message indicating it
					if sb.Len() > 0 {
						sb.WriteString(fmt.Sprintf(", but it was loaded from current execution path %s", currentDir))
						return nil
					}
					sb.WriteString(fmt.Sprintf("Configuration file loaded from current execution path %s", currentDir))
					return nil
				}
				// If we find a file in the path, but we get an error, we exit the search directly
				if sb.Len() > 0 {
					return fmt.Errorf(", error loading file from current execution path %s: %s", currentDir, err)
				}
				return fmt.Errorf("error loading file loaded from current execution path %s: %s", currentDir, err)
			}
		}
		// We have not found a Configuration file in the current execution directory
		if sb.Len() > 0 {
			return fmt.Errorf(", file not found execution path %s", currentDir)
		}
		return fmt.Errorf("configuration file not found in execution path %s", currentDir)
	}(); err != nil {
		sb.WriteString(err.Error())
	} else {
		return sb.String()
	}
	// Finally, we check the folder where the vulnscan binary is located
	if binaryPath, err := osext.ExecutableFolder(); err == nil {
		for p, d := range map[string]gonfig.FileDecoderFn{
			filepath.Join(binaryPath, "vulnscan.toml"): gonfig.DecoderTOML,
			filepath.Join(binaryPath, "vulnscan.yaml"): gonfig.DecoderYAML,
			filepath.Join(binaryPath, "vulnscan.json"): gonfig.DecoderJSON,
		} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				if err := loadConfigurationFile(p, d); err == nil {
					sb.WriteString(fmt.Sprintf(", but it was loaded from the binary path %s", p))
					return sb.String()
				}
				sb.WriteString(fmt.Sprintf(" and error loading the file from binary path %s: %s", p, err))
				return sb.String()
			}
		}
		sb.WriteString(fmt.Sprintf(" and not found in the binary path %s", binaryPath))
		return sb.String()
	}
	// This should not happen
	return fmt.Sprintf("unable to find a valid Configuration file")
}

// CheckScan checks if the scan is in the configuration
func CheckScan(scan string) bool {
	for _, s := range Configuration.Scans {
		if scan == strings.ToLower(s) {
			return true
		}
	}
	return false
}
