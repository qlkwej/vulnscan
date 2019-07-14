package ios

import (
	"github.com/simplycubed/vulnscan/printer/logrus"
	"github.com/simplycubed/vulnscan/utils"
	"strings"
	"testing"
)

func TestListFiles(t *testing.T) {
	zipFile, _ := utils.FindTest("apps", "source.zip")
	path, _ := utils.FindTest("apps", "source")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		if result, err := ListFiles(p); err != nil {
			t.Errorf("List files analysis failed with error %s", err)
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
	if res, e := utils.WithPipeStdout(func() error {
		test, _ := utils.FindTest("apps", "binary.ipa")
		return StaticAnalyzer(test, false, "us", true,
			logrus.NewPrinter(logrus.Log, logrus.Text, logrus.DefaultFormat))
	}); e != nil {
		t.Errorf("ERROR %s", e)
	} else {
		if strings.Index(res, "analysis=virus") == -1 {
			t.Errorf("Virus analysis not found")
		} else if strings.Index(res, "analysis=plist") == -1 {
			t.Errorf("PList analysis not found")
		} else if strings.Index(res, "analysis=store") == -1 {
			t.Errorf("Store analysis not found")
		} else if strings.Index(res, "analysis=files") == -1 {
			t.Errorf("Files analysis not found")
		} else if strings.Index(res, "analysis=code") == -1 {
			t.Errorf("Code analysis not found")
		}
	}
}
