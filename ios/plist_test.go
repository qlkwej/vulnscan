package ios

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestPlistSourceSearch(t *testing.T) {
	path, _ := filepath.Abs("../test_files/plist/source")
	if file, name, err := findPListFile(path, true); err != nil || len(file) == 0 {
		t.Errorf("Failed to find plist file in source with error %s", err)
	} else if len(name) == 0 {
		t.Errorf("Failed to extract name from source")
	}
}

func TestPListBinarySearch(t *testing.T) {
	path, _ := filepath.Abs("../test_files/plist/binary")
	if file, name, err := findPListFile(path, false); err != nil || len(file) == 0 {
		t.Errorf("Failed to find plist file in source with error %s", err)
	} else if len(name) == 0 {
		t.Errorf("Failed to extract name from source")
	}
}

func TestMultiplePListAnalysis(t *testing.T) {
	for i := 1; i <= 5; i++ {
		path, _ := filepath.Abs(fmt.Sprintf("../test_files/plist/plistfiles/plist%d.plist", i))
		if _, err := makePListAnalysis(path, fmt.Sprintf("App%d", i), true); err != nil {
			t.Errorf("Failed to extract plist data from %s with error %s", path, err)
		}
	}
}

func TestPlistSourceAnalysis(t *testing.T) {
	path, _ := filepath.Abs("../test_files/plist/source")
	if result, err := PListAnalysis(path, true); err != nil || len(result.PListXML) == 0 {
		t.Errorf("Plist source analysis failed with error %s", err)
	}
}

func TestPListBinaryAnalysis(t *testing.T) {
	path, _ := filepath.Abs("../test_files/plist/binary")
	if result, err := PListAnalysis(path, false); err != nil || len(result.PListXML) == 0 {
		t.Errorf("Plist source analysis failed with error %s", err)
	}
}