package utils

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
)

func TestResetConfiguration(t *testing.T) {
	Configuration.SourcePath = "somepath"
	ResetConfiguration()
	if Configuration.SourcePath != "" {
		t.Errorf("Error reseting configuration")
	}
}

func TestCheckConfigurationScans(t *testing.T) {
	if err := CheckConfigurationScans([]string{"someBadScan", "plist", "binary"}); err == nil {
		t.Errorf("Error detecting bad scans")
	}
	if err := CheckConfigurationScans([]string{"plist", "plist", "binary"}); err == nil {
		t.Errorf("Error detecting repeating scans")
	}
	if err := CheckConfigurationScans([]string{"binary", "code", "plist", "lookup"}); err != nil {
		t.Errorf("Error parsing good scans: %s", err)
	}
}

var (
	json = func() string {
		f, _ := FindMainFolder()
		return fmt.Sprintf(`{
"scans":  ["binary", "code", "plist"],
"json": true,
"source": "%s/test_files/apps/source.zip",
"binary": "%s/test_files/apps/binary.ipa",
"virus": "virus_scan_password",
"country": "us"
}`, f, f)
	}()

	toml = func() string {
		f, _ := FindMainFolder()
		return fmt.Sprintf(` 
scans = ["binary", "code", "plist"]
json = true
source = "%s/test_files/apps/source.zip"
binary = "%s/test_files/apps/binary.ipa"
virus = "virus_scan_password"
country = "us"`, f, f)
	}()

	yaml = func() string {
		f, _ := FindMainFolder()
		return fmt.Sprintf(`
scans: [binary, code, plist]
json: true
source: %s/test_files/apps/source.zip
binary: %s/test_files/apps/binary.ipa
virus: virus_scan_password
country: us`, f, f)
	}()
)

func TestLoadConfigurationFromPath(t *testing.T) {
	for ext, content := range map[string]string{"toml": toml, "json": json, "yaml": yaml} {
		p, e := FindTest("configuration", "vulnscan."+ext)
		if e != nil {
			t.Error(e)
		}
		e = ioutil.WriteFile(p, []byte(content), 0644)
		if e != nil {
			t.Error(e)
		}
		message := LoadConfiguration(p)
		if !strings.HasPrefix(message, "Configuration file loaded from") {
			t.Errorf("wrong message: %s", message)
		}
		if Configuration.VirusScanKey != "virus_scan_password" ||
			Configuration.JSONFormat != true ||
			!reflect.DeepEqual(Configuration.Scans, []string{"binary", "code", "plist"}) {
			t.Errorf("wrong Configuration found: %v", Configuration)
		}
		// We reset the Configuration for the next loop
		ResetConfiguration()
	}
}

func TestLoadConfigurationFileFromCwd(t *testing.T) {
	fr, _ := FindMainFolder()
	err := ioutil.WriteFile(fr+"/vulnscan.toml", []byte(toml), 0644)
	if err != nil {
		t.Error(err)
	}
	message := LoadConfiguration("")
	if !strings.HasPrefix(message, "Configuration file loaded from current execution path") {
		t.Errorf("wrong message: %s", message)
	}
	message = LoadConfiguration("/some/stupid/path")
	if !strings.HasPrefix(message, "Configuration file not found in /some/stupid/path, but "+
		"it was loaded from current execution path") {
		t.Errorf("wrong message: %s", message)
	}
	if Configuration.VirusScanKey != "virus_scan_password" ||
		Configuration.JSONFormat != true ||
		!reflect.DeepEqual(Configuration.Scans, []string{"binary", "code", "plist"}) {
		t.Errorf("wrong Configuration found: %v", Configuration)
	}
}
