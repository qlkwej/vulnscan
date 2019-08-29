package macho

import (
	"github.com/simplycubed/vulnscan/utils"
	"path/filepath"
	"testing"
)

func TestGetMachoInfo(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		machoInfo, err := GetMachoInfo(binPath)
		if err != nil {
			return err
		}
		if len(machoInfo["bits"]) == 0 || len(machoInfo["endianness"]) == 0 || len(machoInfo["cpu_type"]) == 0 {
			t.Errorf("Some macho analysis did not complete, %#v", machoInfo)
		}
		return nil
	}); e != nil {
		t.Errorf("%s", e)
	}
}
