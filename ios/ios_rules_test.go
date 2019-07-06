package ios

import (
	"fmt"
	"strings"
	"testing"
)

func TestIosRules(t *testing.T) {
	var errors strings.Builder
	for i, p := range  [][2]interface{} {
		{ "int func(char * dest) { strcpy(src, \"string to copy\") } ", true },
		{ "const CFStringRef kCFStreamSSLAllowsExpiredCertificates=(CFStringRef)@\"kCFStreamSSLAllowsExpiredCertificates\";", true },
		{ "setAllowsAnyHTTPSCertificate: YES", true },
		{ "username = |plaintext|", true },
		{ "192.189.0.23", true },
		{ "NSAssert( $(self).CHILDREN().count == self.view.subviews.count, @\" );", true },
		{ "UIPasteboardChanged", false },
		{ "sqlite3", false },
		{ "NSString *path=[NSTemporaryDirectory() stringByAppendingString,@\"bpcities.txt\"];", true },
		{ "webView.loadHTMLString(contents)", true },
		{ "//  SFAntiPiracy.h", false },
		{ "//  SFAntiPiracy.h \n @interface SFAntiPiracy , NSObject\n + (int)isPirated;", true },
		{ "CommonDigest.h text CC_MD5", true },
		{ "commondigest.h text CC_SHA1", false },
		{ "kCCOptionECBMode", false },
		{ "ptrace_ptr pt_denny_attach", false },
		{ "#include <mach/mach_init.h>\n static void retainSendRight(mach_port_t port) { if (!MACH_PORT_VALID(port)) return;", true },
		{ "@select(cut,) || @select(copy,)", false },
		{ "/etc/ssh/sshd_config", true },
	} {
		if CodeRules[i].Match(p[0].(string)) != p[1].(bool) {
			errors.WriteString(fmt.Sprintf("Error in %d test: Expected %t using string %s\n", i, p[1].(bool), p[0].(string)))
		}
	}
	if errors.Len() > 0 {
		t.Errorf("Found errors:\n: %s", errors.String())
	}
}
