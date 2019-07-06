package ios

import (
	"regexp"
	"strings"
)

type Match func(string) bool

type Level int

const (
	High Level = iota
	Warning
	Info
	Good
)

type CodeRule struct {
	Desc string
	Match Match
	Level Level
	Cvss float32
	Cwe string
}

var CodeRules = [...]CodeRule{
	{
		"The App may contain banned API(s). These API(s) are insecure and must not be used.",
		func(s string) bool {
			r, _ := regexp.MatchString(`strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets`, s)
			return r
		},
		High,
		2.2,
		"CWE-676",
	},
	{
		"App allows self signed or invalid SSL certificates. App is vulnerable to MITM attacks.",
		func(s string) bool {
			r, _ := regexp.MatchString(
				`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|` +
					`kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|` +
					`kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|` +
					`allowInvalidCertificates\s*=\s*(YES|yes)`, s)
			return r
		},
		High,
		7.4,
		"CWE-295",
	},
	{
		"UIWebView in App ignore SSL errors and accept any SSL Certificate. App is vulnerable to MITM attacks.",
		func(s string) bool {
			r, _ := regexp.MatchString(
				`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|` +
				`loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`, s)
			return r
		},
		High,
		7.4,
		`CWE-295`,
	},
	{
		"Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
		func(s string) bool {
			r, _ := regexp.MatchString(
				`(password\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*@*\s*['|"].+['|"]\s{0,5})|` +
					`(username\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*@*\s*['|"].+['|"]\s{0,5})|` +
					`(key\s*=\s*@*\s*['|"].+['|"]\s{0,5})`, strings.ToLower(s))
			return r
		},
		High,
		7.4,
		"CWE-312",
	},
	{
		"IP Address disclosure",
		func(s string) bool {
			r, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, s)
			return r
		},
		Warning,
		4.3,
		"CWE-200",
	},
	{
		"The App logs information. Sensitive information should never be logged.",
		func(s string) bool {
			r, _ := regexp.MatchString(`NSLog|NSAssert|fprintf|Logging`, s)
			return r
		},
		Info,
		7.5,
		"CWE-532",
	},
	{
		"This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.",
		func(s string) bool {
			r, _ := regexp.MatchString(`UIPasteboardChangedNotification|generalPasteboard]\.string`, s)
			return r
		},
		Warning,
		0,
		"",
	},
	{
		"App uses SQLite Database. Sensitive Information should be encrypted.",
		func(s string) bool {
			return strings.Contains(s, "sqlite3_exec")
		},
		Info,
		0,
		"",
	},
	{
		"Untrusted user input to \"NSTemporaryDirectory()\" will result in path traversal vulnerability.",
		func(s string) bool {
			return strings.Contains(s, "NSTemporaryDirectory(),")
		},
		Warning,
		7.5,
		"CWE-22",
	},
	{
		"User input in \"loadHTMLString\" will result in JavaScript Injection.",
		func(s string) bool {
			return strings.Contains(s, "loadHTMLString") && strings.Contains(s, "webView")
		},
		Warning,
		8.8,
		"CWE-95",
	},
	{
		"SFAntiPiracy Jailbreak checks found",
		func(s string) bool {
			return strings.Contains(s, "SFAntiPiracy.h") && strings.Contains(s, "SFAntiPiracy") &&
				strings.Contains(s, "isJailbroken")
		},
		Good,
		0,
		"",
	},
	{
		"SFAntiPiracy Piracy checks found",
		func(s string) bool {
			return strings.Contains(s, "SFAntiPiracy.h") && strings.Contains(s, "SFAntiPiracy") &&
				strings.Contains(s, "isPirated")
		},
		Good,
		0,
		"",
	},
	{
		"MD5 is a weak hash known to have hash collisions.",
		func(s string) bool {
			return strings.Contains(s, "CommonDigest.h") && strings.Contains(s, "CC_MD5")
		},
		High,
		7.4,
		"CWE-327",
	},
	{
		"SHA1 is a weak hash known to have hash collisions.",
		func(s string) bool {
			return strings.Contains(s, "CommonDigest.h") && strings.Contains(s, "CC_SHA1")
		},
		High,
		7.4,
		"CWE-327",
	},
	{
		"The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is known to be weak as it " +
			"results in the same ciphertext for identical blocks of plaintext.",
		func(s string) bool {
			return strings.Contains(s, "kCCOptionECBMode") && strings.Contains(s, "kCCAlgorithmAES")
		},
		High,
		5.9,
		"CWE-327",
	},
	{
		"The App has ant-debugger code using ptrace()",
		func(s string) bool {
			return strings.Contains(s, "ptrace_ptr") && strings.Contains(s, "PT_DENY_ATTACH")
		},
		Info,
		0,
		"",
	},
	{
		"This App has anti-debugger code using Mach Exception Ports.",
		func(s string) bool {
			return strings.Contains(s, "mach/mach_init.h") && (strings.Contains(s, "MACH_PORT_VALID") ||
				strings.Contains(s, "mach_task_self()"))
		},
		Info,
		0,
		"",
	},
	{
		"This App copies data to clipboard. Sensitive data should not be copied to clipboard as other " +
			"applications can access it.",
		func(s string) bool {
			return strings.Contains(s, "UITextField") && (strings.Contains(s, "@select(cut:)") ||
				strings.Contains(s, "@select(copy:)"))
		},
		Info,
		0,
		"",
	},
	{
		"This App may have Jailbreak detection capabilities.",
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
		Good,
		0,
		"",
	},
}