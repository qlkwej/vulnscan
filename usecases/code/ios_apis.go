package code

import (
	"github.com/simplycubed/vulnscan/entities"
	"regexp"
	"strings"
)

var APIs = []entities.ApiMatcher{
	{
		ApiRule: entities.ApiRule{
			Description: "Network Calls",
		},
		Match: func(s string) bool {
			r, _ := regexp.MatchString(`NSURL|CFStream|NSStream`, s)
			return r
		},
	},
	{ApiRule: entities.ApiRule{
		Description: "Local File I/O Operations.",
	},
		Match: func(s string) bool {
			r, _ := regexp.MatchString(
				`Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|`+`
				SecItemUpdate|NSDataWritingFileProtectionComplete`, s)
			return r
		},
	},
	{
		ApiRule: entities.ApiRule{
			Description: "WebView Component",
		},
		Match: func(s string) bool {
			r, _ := regexp.MatchString("UIWebView", s)
			return r
		},
	},
	{
		ApiRule: entities.ApiRule{
			Description: "Encryption API",
		},
		Match: func(s string) bool {
			r, _ := regexp.MatchString("RNEncryptor|RNDecryptor|AESCrypt", s)
			return r
		},
	},
	{
		ApiRule: entities.ApiRule{
			Description: "Keychain Access",
		},
		Match: func(s string) bool {
			return strings.Contains(s, "PDKeychainBindings")
		},
	},
	{
		ApiRule: entities.ApiRule{
			Description: "WebView Load Request",
		},
		Match: func(s string) bool {
			return strings.Contains(s, "loadRequest") && strings.Contains(s, "webView")
		},
	},
}
