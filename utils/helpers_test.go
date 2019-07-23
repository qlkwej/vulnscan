package utils

import "testing"

func TestCheckPathIsSrc(t *testing.T) {
	goodSrc, _ := FindTest("unzip", "source")
	badSrc, _ := FindTest("unzip", "badSource")
	goodBin, _ := FindTest("apps", "binary.ipa")
	badBin, _ := FindTest("apps", "no_binary.ipa")
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("wrong paths did not panic")
		}
	}()
	if p, isSrc := CheckPathIsSrc("", goodSrc); p != goodSrc || !isSrc {
		t.Errorf("error identifying source path: %v - %v", p, isSrc)
	}
	if p, isSrc := CheckPathIsSrc(goodBin, ""); p != goodBin || isSrc {
		t.Errorf("error identifying binary path: %v - %v", p, isSrc)
	}
	_, _ = CheckPathIsSrc(badSrc, badBin)
}
