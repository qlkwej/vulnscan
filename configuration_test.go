package main

import (
	"github.com/simplycubed/vulnscan/utils"
	"reflect"
	"strings"
	"testing"
)

func TestLoadConfigurationFromPath(t *testing.T) {
	for _, ext := range []string {"toml", "json", "yaml"} {
		p, e := utils.FindTest("configuration", "vulnscan." + ext)
		if e != nil {
			t.Error(e)
		}
		message := loadConfiguration(p)
		if !strings.HasPrefix(message, "configuration file loaded from") {
			t.Errorf("wrong message: %s", message)
		}
		if configuration.VirusScanKey != "virus_scan_password" ||
			configuration.JsonFormat != true ||
			!reflect.DeepEqual(configuration.Scans, []string{"binary", "code", "plist", "static"}) {
			t.Errorf("wrong configuration found: %v", configuration)
		}

		// We reset the configuration for the next loop
		configuration =  struct {
			Scans        []string `id:"scans" short:"s" desc:"Test to do when calling scan command"`
			JsonFormat   bool     `id:"json" short:"o" desc:"Activate the json output"`
			SourcePath   string   `id:"source" short:"sp" desc:"Path to the source code to analyze"`
			BinaryPath   string   `id:"binary" short:"bp" desc:"Path to the binary .ipa file to analyze"`
			VirusScanKey string   `id:"virus" short:"v" desc:"Virus Scan API key to use the service"`
		}{
			Scans:        []string{"binary", "code", "plist", "static", "store"},
			JsonFormat:   false,
			SourcePath:   "",
			BinaryPath:   "",
			VirusScanKey: "",
		}
	}
}

func TestLoadConfigurationFileFromCwd(t *testing.T) {
	message := loadConfiguration("")
	if !strings.HasPrefix(message, "configuration file loaded from current execution path") {
		t.Errorf("wrong message: %s", message)
	}
	message = loadConfiguration("/some/stupid/path")
	if !strings.HasPrefix(message, "configuration file not found in /some/stupid/path, but " +
		"it was loaded from current execution path") {
		t.Errorf("wrong message: %s", message)
	}
	if configuration.VirusScanKey != "virus_scan_password" ||
		configuration.JsonFormat != true ||
		!reflect.DeepEqual(configuration.Scans, []string{"binary", "code", "plist", "static"}) {
		t.Errorf("wrong configuration found: %v", configuration)
	}
}
