package ios

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)



func TestGetOtoolOut(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		otoolOut, err := getOtoolOut(binPath, Libs)
		if err != nil {
			return err
		}
		if platform := runtime.GOOS; platform == "darwin" {
			if !strings.Contains(otoolOut,
				"/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 1560.10.0)")	{
				t.Errorf("Wrong otool output for libs command: %s", otoolOut)
			}
		} else if platform == "linux" {
			if !strings.Contains(otoolOut,
				"/System/Library/Frameworks/Foundation.framework/Foundation (compatibility ver: 300.0.0, current ver: 1560.10.0)")	{
				t.Errorf("Wrong otool output for libs command: %s", otoolOut)
			}
		}
		otoolOut, err = getOtoolOut(binPath, Header)
		if err != nil {
			return err
		}
		if !strings.Contains(otoolOut,
			"PIE")	{
			t.Errorf("Wrong otool output for header command: %s", otoolOut)
		}
		otoolOut, err = getOtoolOut(binPath, Symbols)
		if err != nil {
			return err
		}
		if !strings.Contains(otoolOut, "address") || !strings.Contains(otoolOut, "index") ||
			!strings.Contains(otoolOut, "name") {
			t.Errorf("Wrong otool output for symbols command: %s", otoolOut)
		}
		return nil
	}); e != nil {
		t.Errorf("%s", e)
	}
}

func TestGetOtoolOutForceLinux(t *testing.T) {
	mainFolder, _ := utils.FindMainFolder()
	err := godotenv.Load(mainFolder + string(os.PathSeparator) + ".env")
	if err != nil {
		t.Error("Error loading .env file")
	}
	if os.Getenv("FORCE_LINUX") != "1" {
		t.Error("Error loading FORCE_LINUX environment variable")
	}
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		otoolOut, err := getOtoolOut(binPath, Libs)
		if err != nil {
			return err
		}
		if !strings.Contains(otoolOut,
			"/System/Library/Frameworks/Foundation.framework/Foundation (compatibility ver: 300.0.0, current ver: 1560.10.0)")	{
			t.Errorf("Wrong otool output for libs command: %s", otoolOut)
		}
		otoolOut, err = getOtoolOut(binPath, Header)
		if err != nil {
			return err
		}
		if !strings.Contains(otoolOut,
			"PIE")	{
			t.Errorf("Wrong otool output for header command: %s", otoolOut)
		}
		otoolOut, err = getOtoolOut(binPath, Symbols)
		if err != nil {
			return err
		}
		if !strings.Contains(otoolOut, "address") || !strings.Contains(otoolOut, "index") ||
			!strings.Contains(otoolOut, "name") {
			t.Errorf("Wrong otool output for symbols command: %s", otoolOut)
		}
		return nil
	}); e != nil {
		t.Errorf("%s", e)
	}
}

func TestOtoolAnalysis(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		analysis, err := otoolAnalysis(binPath)
		if err != nil {
			return err
		}
		if libsLen:=len(analysis["libs"].([]string)); libsLen != 25 {
			t.Errorf("wrong number of libraries found, expected %d, found %d", 25, libsLen)
		}
		if analLen:=len(analysis["anal"].([]map[string]interface{})); analLen != 12 {
			t.Errorf("wrong number of analysis found, expected %d, found %d", 12, analLen)
		}
		return nil
	}); e != nil {
		t.Errorf("%s", e)
	}
}

func TestDetectBinType(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		otoolOut, err := getOtoolOut(binPath, Libs)
		if err != nil {
			return err
		}
		libs := strings.Split(otoolOut, "\n")
		if detectBinType(libs) != Swift {
			t.Error("Wrong binary type detection")
		}
		return nil
	}); e != nil {
		t.Error(e)
	}
}

func TestClassDump(t *testing.T) {
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		dump, err := classDump(binPath, Swift)
		if err != nil {
			return err
		}
		if issue := dump["issue"].(string); issue != "Binary doesn't use WebView Component." {
			t.Errorf("Wrong issue message: %s", issue)
		}
		return nil
	}); e != nil {
		t.Error(e)
	}
}

func TestClassDumpForceLinux(t *testing.T) {
	mainFolder, _ := utils.FindMainFolder()
	err := godotenv.Load(mainFolder + string(os.PathSeparator) + ".env")
	if err != nil {
		t.Error("Error loading .env file")
	}
	if os.Getenv("FORCE_LINUX") != "1" {
		t.Error("Error loading FORCE_LINUX environment variable")
	}
	path, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(path, false, func(p string) error {
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		binPath := filepath.Join(appPath, "iVim")
		dump, err := classDump(binPath, Swift)
		if err != nil {
			return err
		}
		if issue := dump["issue"].(string); issue != "Binary doesn't use WebView Component." {
			t.Errorf("Wrong issue message: %s", issue)
		}
		return nil
	}); e != nil {
		t.Error(e)
	}
}

func TestBinaryAnalysis(t *testing.T) {
	ipaPath, _ := utils.FindTest("apps", "binary.ipa")
	analysis, err := BinaryAnalysis(ipaPath, false, "iVim")
	if err != nil {
		t.Errorf("Error generating binary analysis: %s", err)
	} else {
		if binResLen := len(analysis["bin_res"].([]map[string]interface{})); binResLen != 13 {
			t.Errorf("Wrong bin_res number of results: %d, expected %d", binResLen, 13)
		}
		if libsLen := len(analysis["libs"].([]string)); libsLen != 25 {
			t.Errorf("Wrong detected number of libs: %d, expected %d", libsLen, 25)

		}
		if analysis["bin_type"].(string) != "Swift" {
			t.Error("Wrong binary type detection")
		}
		if machoInfo := analysis["macho"].(map[string]string); len(machoInfo["bits"]) == 0 ||
			len(machoInfo["endianness"]) == 0 || len(machoInfo["cpu_type"]) == 0 {
			t.Errorf("Some macho analysis did not complete, %#v", machoInfo)
		}

	}
}
