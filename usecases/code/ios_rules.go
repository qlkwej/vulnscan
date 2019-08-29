package code

import (
	"github.com/simplycubed/vulnscan/entities"
	"regexp"
	"strings"
)

type Match func(string) bool

type Level int

var Rules = [...]entities.CodeMatcher{
	{
		entities.CodeRule{
			Description: "The App may contain banned API(s). These API(s) are insecure and must not be used.",
			Level:       entities.HighLevel,
			Cvss:        2.2,
			Cwe:         "CWE-676",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(`strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "App allows self signed or invalid SSL certificates. App is vulnerable to MITM attacks.",
			Level:       entities.HighLevel,
			Cvss:        7.4,
			Cwe:         "CWE-295",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(
				`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|`+
					`kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|`+
					`kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|`+
					`allowInvalidCertificates\s*=\s*(YES|yes)`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "UIWebView in App ignore SSL errors and accept any SSL Certificate. App is vulnerable to MITM attacks.",
			Level:       entities.HighLevel,
			Cvss:        7.4,
			Cwe:         `CWE-295`,
		},
		func(s string) bool {
			r, _ := regexp.MatchString(
				`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|`+
					`loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
			Level:       entities.HighLevel,
			Cvss:        7.4,
			Cwe:         "CWE-312",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(
				`(password\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*@*\s*['|"].+['|"]\s{0,5})|`+
					`(username\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*@*\s*['|"].+['|"]\s{0,5})|`+
					`(key\s*=\s*@*\s*['|"].+['|"]\s{0,5})`, strings.ToLower(s))
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "IP Address disclosure",
			Level:       entities.WarningLevel,
			Cvss:        4.3,
			Cwe:         "CWE-200",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "The App logs information. Sensitive information should never be logged.",
			Level:       entities.InfoLevel,
			Cvss:        7.5,
			Cwe:         "CWE-532",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(`NSLog|NSAssert|fprintf|Logging`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.",
			Level:       entities.WarningLevel,
			Cvss:        0.,
			Cwe:         "",
		},
		func(s string) bool {
			r, _ := regexp.MatchString(`UIPasteboardChangedNotification|generalPasteboard]\.string`, s)
			return r
		},
	},
	{
		entities.CodeRule{
			Description: "App uses SQLite Database. Sensitive Information should be encrypted.",
			Level:       entities.InfoLevel,
			Cvss:        0.,
			Cwe:         "",
		},
		func(s string) bool {
			return strings.Contains(s, "sqlite3_exec")
		},
	},
	{
		entities.CodeRule{
			Description: "Untrusted user input to \"NSTemporaryDirectory()\" will result in path traversal vulnerability.",
			Level:       entities.WarningLevel,
			Cvss:        7.5,
			Cwe:         "CWE-22",
		},
		func(s string) bool {
			return strings.Contains(s, "NSTemporaryDirectory()")
		},
	},
	{
		entities.CodeRule{
			Description: "User input in \"loadHTMLString\" will result in JavaScript Injection.",
			Level:       entities.WarningLevel,
			Cvss:        8.8,
			Cwe:         "CWE-95",
		},
		func(s string) bool {
			return strings.Contains(s, "loadHTMLString") && strings.Contains(s, "webView")
		},
	},
	{
		entities.CodeRule{
			Description: "SFAntiPiracy Jailbreak checks found",
			Level:       entities.GoodLevel,
			Cvss:        0,
			Cwe:         "",
		},
		func(s string) bool {
			return strings.Contains(s, "SFAntiPiracy.h") && strings.Contains(s, "SFAntiPiracy") &&
				strings.Contains(s, "isJailbroken")
		},
	},
	{
		entities.CodeRule{
			Description: "SFAntiPiracy Piracy checks found",
			Level:       entities.GoodLevel,
			Cvss:        0,
			Cwe:         "",
		},
		func(s string) bool {
			return strings.Contains(s, "SFAntiPiracy.h") && strings.Contains(s, "SFAntiPiracy") &&
				strings.Contains(s, "isPirated")
		},
	},
	{
		entities.CodeRule{
			Description: "MD5 is a weak hash known to have hash collisions.",
			Level:       entities.HighLevel,
			Cvss:        7.4,
			Cwe:         "CWE-327",
		},
		func(s string) bool {
			return strings.Contains(s, "CommonDigest.h") && strings.Contains(s, "CC_MD5")
		},
	},
	{
		entities.CodeRule{
			Description: "SHA1 is a weak hash known to have hash collisions.",
			Level:       entities.HighLevel,
			Cvss:        7.4,
			Cwe:         "CWE-327",
		},
		func(s string) bool {
			return strings.Contains(s, "CommonDigest.h") && strings.Contains(s, "CC_SHA1")
		},
	},
	{
		entities.CodeRule{
			Description: "The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is known to be weak as it " +
				"results in the same ciphertext for identical blocks of plaintext.",
			Level: entities.HighLevel,
			Cvss:  5.9,
			Cwe:   "CWE-327",
		},
		func(s string) bool {
			return strings.Contains(s, "kCCOptionECBMode") && strings.Contains(s, "kCCAlgorithmAES")
		},
	},
	{
		entities.CodeRule{
			Description: "The App has anti-debugger code using ptrace()",
			Level:       entities.HighLevel,
			Cvss:        0,
			Cwe:         "",
		},
		func(s string) bool {
			return strings.Contains(s, "ptrace_ptr") && strings.Contains(s, "PT_DENY_ATTACH")
		},
	},
	{
		entities.CodeRule{
			Description: "This App has anti-debugger code using Mach Exception Ports.",
			Level:       entities.InfoLevel,
			Cvss:        0,
			Cwe:         "",
		},
		func(s string) bool {
			return strings.Contains(s, "mach/mach_init.h") && (strings.Contains(s, "MACH_PORT_VALID") ||
				strings.Contains(s, "mach_task_self()"))
		},
	},
	{
		entities.CodeRule{
			Description: "This App copies data to clipboard. Sensitive data should not be copied to clipboard as other " +
				"applications can access it.",
			Level: entities.InfoLevel,
			Cvss:  0,
			Cwe:   "",
		},
		func(s string) bool {
			return strings.Contains(s, "UITextField") && (strings.Contains(s, "@select(cut:)") ||
				strings.Contains(s, "@select(copy:)"))
		},
	},
	{
		entities.CodeRule{
			Description: "This App may have Jailbreak detection capabilities.",
			Level:       entities.GoodLevel,
			Cvss:        0,
			Cwe:         "",
		},
		func(s string) bool {
			for _, m := range []string{
				"/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
				"/usr/sbin/sshd", "/etc/apt", "cydia://", "/var/lib/cydia", "/Applications/FakeCarrier.app",
				"/Applications/Icy.app", "/Applications/IntelliScreen.app", "/Applications/SBSettings.app",
				"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
				"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
				"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
				"/etc/ssh/sshd_config", "/private/var/tmp/cydia.log", "/usr/libexec/ssh-keysign",
				"/Applications/MxTube.app", "/Applications/RockApp.app", "/Applications/WinterBoard.app",
				"/Applications/blackra1n.app", "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
				"/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/mobile/Library/SBSettings/Themes",
				"/private/var/stash", "/usr/bin/sshd", "/usr/libexec/sftp-server", "/var/cache/apt",
				"/var/lib/apt", "/usr/sbin/frida-server", "/usr/bin/cycript", "/usr/local/bin/cycript",
				"/usr/lib/libcycript.dylib", "frida-server",
			} {
				if strings.Contains(s, m) {
					return true
				}
			}
			return false
		},
	},
}
