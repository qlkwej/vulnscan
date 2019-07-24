package ios

import (
	"fmt"
	"testing"

	"github.com/simplycubed/vulnscan/utils"
)


func TestPlistSourceSearch(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "source.zip")
	path, _ := utils.FindTest("apps", "source")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if file, name, err := findPListFile(p, true); err != nil || len(file) == 0 {
			t.Errorf("Failed to find plist file in source with error %s", err)
		} else if len(name) == 0 {
			t.Errorf("Failed to extract name from source")
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPListBinarySearch(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "binary.ipa")
	path, _ := utils.FindTest("apps", "binary")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if file, name, err := findPListFile(p, false); err != nil || len(file) == 0 {
			t.Errorf("Failed to find plist file in source with error %s", err)
		} else if len(name) == 0 {
			t.Errorf("Failed to extract name from source")
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestMultiplePListAnalysis(t *testing.T) {
	for i := 1; i <= 5; i++ {
		path, _ := utils.FindTest("plist", fmt.Sprintf("plist%d.plist", i))
		if a, err := makePListAnalysis(path, fmt.Sprintf("App%d", i), true); err != nil {
			t.Errorf("Failed to extract plist data from %s with error %s", path, err)
		} else {
			t.Errorf("%#v", a)
		}
	}
}

func TestPlistSourceAnalysis(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "source.zip")
	path, _ := utils.FindTest("apps", "source")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if result, err := PListAnalysis(p, true); err != nil || len(result["plist_XML"].(string)) == 0 {
			t.Errorf("Plist source analysis failed with error %s", err)
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPListBinaryAnalysis(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "binary.ipa")
	path, _ := utils.FindTest("apps", "binary")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if result, err := PListAnalysis(p, false); err != nil || len(result["plist_XML"].(string)) == 0 {
			t.Errorf("Plist source analysis failed with error %s", err)
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}