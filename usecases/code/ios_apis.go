package code

import (
	"github.com/simplycubed/vulnscan/entities"
	"regexp"
	"strings"
)


var APIs = []entities.ApiMatcher{
	{
		entities.ApiRule{
			Description: "Network Calls",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(`NSURL|CFStream|NSStream`, s)
			return r
		},
	},
	{ entities.ApiRule{
			Description: "Local File Inf/O Operations.",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(
				`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|`+`
				SecItemUpdate|NSDataWritingFileProtectionComplete`, s)
			return r
		},
	},
	{
		entities.ApiRule{
			Description: "WebView Component",
		},
		func(s string) bool {
			r, _ := regexp.MatchString("UIWebView", s)
			return r
		},
	},
	{
		entities.ApiRule{
			Description: "Encryption API",
		},
		func(s string) bool {
			r, _ := regexp.MatchString("RNEncryptor|RNDecryptor|AESCrypt", s)
			return r
		},
	},
	{
		entities.ApiRule{
			Description:"Keychain Access",
		},
		func(s string) bool {
			return strings.Contains(s, "PDKeychainBindings")
		},
	},
	{
		entities.ApiRule{
			Description: "WebView Load Request",
		},
		func(s string) bool {
			return strings.Contains(s, "loadRequest") && strings.Contains(s, "webView")
		},
	},
}
