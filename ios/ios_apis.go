package ios

import (
	"regexp"
	"strings"
)

type CodeAPI struct {
	Desc  string
	Match Match
}

var CodeAPIs = []CodeAPI {
	{
		"Network Calls",
		func(s string) bool {
			r, _ := regexp.MatchString(`NSURL|CFStream|NSStream`, s)
			return r
		},
	},
	{
		"Local File I/O Operations.",
		func(s string) bool {
			r, _ := regexp.MatchString(
				`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|` + `
				SecItemUpdate|NSDataWritingFileProtectionComplete`, s)
			return r
		},
	},
	{
		"WebView Component",
		func(s string) bool {
			r, _ := regexp.MatchString("UIWebView", s)
			return r
		},
	},
	{
		"Encryption API",
		func(s string) bool {
			r, _ := regexp.MatchString("RNEncryptor|RNDecryptor|AESCrypt", s)
			return r
		},
	},
	{
		"Keychain Access",
		func(s string) bool {
			return strings.Contains(s, "PDKeychainBindings")
		},
	},
	{
		"WebView Load Request",
		func(s string) bool {
			return strings.Contains(s, "loadRequest") && strings.Contains(s, "webView")
		},
	},
}
