package utils

import "testing"

func TestHashMD5(t *testing.T) {
	file, _ := FindTest("apps", "binary.ipa")
	if hash, e := HashMD5(file); e != nil {
		t.Error(e)
	} else if len(hash) != 32 {
		t.Errorf("Invalid hash length: %d", len(hash))
	}
}
