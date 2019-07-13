package ios

import (
	"github.com/simplycubed/vulnscan/utils"
	"testing"
)

func TestListFiles(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "source.zip")
	path, _ := utils.FindTest("apps", "source")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if result, err := ListFiles(p); err != nil {
			t.Errorf("Plist source analysis failed with error %s", err)
		} else {
			if  len(result["certs"].([]string)) > 0 ||
				len(result["database"].([]string)) > 0 ||
				len(result["files"].([]string)) < 2 ||
				len(result["plist"].([]string))< 1 {
				t.Errorf("found unexpected number of files")
			}
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestStaticAnalyzer(t *testing.T) {

}
