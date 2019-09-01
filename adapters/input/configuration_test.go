package input

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/adapters/tools"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)


var (
	command = entities.Command{}
	adapter = defaultAdapterMap()

	defaultAdapterMap = func() adapters.AdapterMap {
		return adapters.AdapterMap{
			Services: adapters.ServiceAdapters {
				MalwareDomains: nil,
				VirusScan:      nil,
			},
			Tools: adapters.ToolAdapters {
				ClassDump: tools.JtoolClassDumpAdapter,
				Libs:      tools.JtoolLibsAdapter,
				Headers:   tools.JtoolHeadersAdapter,
				Symbols:   tools.JtoolSymbolsAdapter,
			},
			Output: adapters.OutputAdapters {
				Logger: output.BasicLoggerAdapter,
				Result: output.PrettyConsoleAdapter,
				Error:  output.BasicErrorAdapter,
			},
		}
	}

	reset = func() {
		command = entities.Command{}
		adapter = defaultAdapterMap()
	}

	json = func() string {
		f, _ := test.FindMainFolder()
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
		f, _ := test.FindMainFolder()
		return fmt.Sprintf(` 
scans = ["binary", "code", "plist"]
json = true
source = "%s/test_files/apps/source.zip"
binary = "%s/test_files/apps/binary.ipa"
virus = "virus_scan_password"
country = "us"`, f, f)
	}()

	yaml = func() string {
		f, _ := test.FindMainFolder()
		return fmt.Sprintf(`
scans: [binary, code, plist]
json: true
source: %s/test_files/apps/source.zip
binary: %s/test_files/apps/binary.ipa
virus: virus_scan_password
country: us`, f, f)
	}()
)

func TestConfigurationAdapterFromPath(t *testing.T) {
	for ext, content := range map[string]string{"toml": toml, "json": json, "yaml": yaml} {
		p, e := test.FindTest("configuration", "vulnscan."+ext)
		assert.NoError(t, e)
		assert.NoError(t, ioutil.WriteFile(p, []byte(content), 0644))
		ConfigurationAdapter(entities.Command{Path: p}, &command, &adapter)

		// TODO: MAKE CHECKS

		// Reset the Configuration for the next loop
		reset()
	}
}

func TestConfigurationAdapterFromCwd(t *testing.T) {
	fr, e := test.FindMainFolder()
	assert.NoError(t, e)
	for ext, content := range map[string]string{"toml": toml, "json": json, "yaml": yaml} {
		p := fr + "/vulnscan." + ext
		e = ioutil.WriteFile(p, []byte(content), 0644)
		ConfigurationAdapter(entities.Command{Path: p}, &command, &adapter)

		// TODO: MAKE CHECKS

		// Reset the Configuration for the next loop
		reset()
	}
}


