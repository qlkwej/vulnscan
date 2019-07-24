package ios

import (
	"github.com/simplycubed/vulnscan/utils"
	"testing"
)

func TestUrlExtract(t *testing.T) {
	urls, _ := urlEmailExtract("data:theCipherText")
	if len(urls) > 0 {
		t.Errorf("Regexp too loose")
	}
	urls, _ = urlEmailExtract("http://code.google.com/p/smhasher")
	if len(urls) == 0  {
		t.Errorf("Regexp invalid")
	}
}

func TestCodeAnalysis(t *testing.T) {
	utils.Configuration.PerformDomainCheck = true
	zipFile, _ := utils.FindTest("apps", "vulnerable_app.zip")
	path, _ := utils.FindTest("apps", "vulnerable_app")
	if err:= utils.WithUnzip(zipFile, path, func(p string) error {
		result, e := CodeAnalysis(p)
		if e != nil {
			t.Error(e)
		} else {
			for k, v := range result {
				if (k == "code" || k == "api") && len(v.(map[string]map[string]interface{})) == 0 {
					t.Errorf("Analysis %s failed", k)
				} else if (k == "url" || k == "email") && len(v.(map[string][]string)) == 0 {
					t.Errorf("Analysis %s failed", k)
				}
			}
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}
