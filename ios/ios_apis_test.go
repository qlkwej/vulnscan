package ios

import (
	"fmt"
	"strings"
	"testing"
)

func TestIosAPIs(t *testing.T) {
	var errors strings.Builder
	for i, p := range [][2]interface{}{
		{"CFStream", true}, {"kSecAttrAccessibleWhenLocked", false}, {"UIWebView", true}, {"RNDecryptor", true},
		{"PDKeychainBindings", true}, {"loadRequest", false},
	} {
		if CodeAPIs[i].Match(p[0].(string)) != p[1].(bool) {
			errors.WriteString(fmt.Sprintf("Error in %d test: Expected %t using string %s\n", i, p[1].(bool), p[0].(string)))
		}
	}
	if errors.Len() > 0 {
		t.Errorf("Found errors:\n: %s", errors.String())
	}
}
