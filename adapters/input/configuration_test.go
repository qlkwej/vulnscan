package input

import (
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/mocks"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/adapters/tools"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

var (
	command = entities.Command{}
	adapter = defaultAdapterMap()

	defaultAdapterMap = func() adapters.AdapterMap {
		return adapters.AdapterMap{
			Services: adapters.ServiceAdapters{
				MalwareDomains: nil,
				VirusScan:      nil,
			},
			Tools: adapters.ToolAdapters{
				ClassDump: tools.JtoolClassDumpAdapter,
				Libs:      tools.JtoolLibsAdapter,
				Headers:   tools.JtoolHeadersAdapter,
				Symbols:   tools.JtoolSymbolsAdapter,
			},
			Output: adapters.OutputAdapters{
				Logger: mocks.LogAdapter,
				Result: output.PrettyConsoleAdapter,
				Error:  mocks.ErrorAdapter,
			},
		}
	}

	reset = func() {
		command = entities.Command{}
		adapter = defaultAdapterMap()
	}

	json = `{
"scans":  ["binary", "code", "plist"],
"json": true,
"source": "test_files/apps/source.zip",
"tools": "tools/folder",
"virus": "virus_scan_password",
"country": "es",
"silent": true,
"domains": true
}`

	toml = ` 
scans = ["binary", "code", "plist"]
json = true
source = "test_files/apps/source.zip"
tools = "tools/folder"	
virus = "virus_scan_password"
country = "es"
silent = true
domains = true`

	yaml = `
scans: [binary, code, plist]
json: true
source: test_files/apps/source.zip
tools: tools/folder	
virus: virus_scan_password
country: es
silent: true
domains: true`
)

func testConfigurationHelper(p string, t *testing.T) {
	ConfigurationAdapter(entities.Command{Path: p, T: t}, &command, &adapter)
	assert.Equal(t, map[entities.AnalysisCheck]bool{
		entities.DoBinary: true,
		entities.DoCode:   true,
		entities.DoPList:  true,
	}, command.Analysis)
	assert.Equal(t, "test_files/apps/source.zip", command.SourcePath)
	assert.Equal(t, "virus_scan_password", command.VirusTotalKey)
	assert.Equal(t, "es", command.Country)
	assert.NotNil(t, adapter.Services.MalwareDomains)
	assert.NotNil(t, adapter.Services.VirusScan)
}

func TestConfigurationAdapterFromPath(t *testing.T) {
	f, e := test.FindTest("configuration")
	assert.NoError(t, e)
	assert.NoError(t, os.MkdirAll(f, os.ModePerm))
	for ext, content := range map[string]string{"toml": toml, "json": json, "yaml": yaml} {
		p, e := test.FindTest("configuration", "vulnscan."+ext)
		assert.NoError(t, e)
		assert.NoError(t, ioutil.WriteFile(p, []byte(content), 0644))
		testConfigurationHelper(p, t)
		// Reset the Configuration for the next loop
		reset()
		assert.NoError(t, os.Remove(p))
	}
}

func TestConfigurationAdapterFromCwd(t *testing.T) {
	fr, e := test.FindMainFolder()
	assert.NoError(t, e)
	for ext, content := range map[string]string{"toml": toml, "json": json, "yaml": yaml} {
		p := fr + "/vulnscan." + ext
		_ = ioutil.WriteFile(p, []byte(content), 0644)
		testConfigurationHelper(p, t)
		// Reset the Configuration for the next loop
		reset()
		assert.NoError(t, os.Remove(p))
	}
}

func TestDefaultConfiguration(t *testing.T) {
	ConfigurationAdapter(entities.Command{Path: "", T: t}, &command, &adapter)
	assert.Equal(t, map[entities.AnalysisCheck]bool{
		entities.DoPList:  true,
		entities.DoBinary: true,
		entities.DoFiles:  true,
		entities.DoStore:  true,
		entities.DoCode:   true,
	}, command.Analysis)
	assert.Equal(t, getToolsFolder(), command.Tools)
	assert.Equal(t, "us", command.Country)
}
