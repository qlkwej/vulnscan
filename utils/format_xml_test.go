package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const plistExample = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key> <string>MoreSettings</string>
	<key>CFBundleIconFiles</key>
	<array>
		<string>Icon.png</string>
		<string>Icon@2x.png</string>
		<string>Icon@3x.png</string>
	</array>
	<key>CFBundleIcons</key>
	<dict>
		<key>CFBundlePrimaryIcon</key>
		<dict>
			<key>CFBundleIconFiles</key>
			<array>
				<string>Icon.png</string>
				<string>Icon@2x.png</string>
				<string>Icon@3x.png</string>
			</array>
			<key>UIPrerenderedIcon</key> <string>true</string>
		</dict>
	</dict>

	<key>CFBundleIdentifier</key> <string>org.h6nry.moresettings</string>
	<key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
	<key>CFBundlePackageType</key> <string>APPL</string>
	<key>CFBundleSignature</key> <string>????</string>
	<key>CFBundleSupportedPlatforms</key>
</dict>
</plist>
`

func TestFormatXML(t *testing.T) {
	assert.Equal(t, "\t\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\t  " +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\r\n\t  " +
		"<plist version=\"1.0\">\r\n\t    <dict>\r\n\t      <key>\r\n\t        CFBundleExecutable</key>\r\n\t      " +
		"<string>\r\n\t        MoreSettings</string>\r\n\t      <key>\r\n\t        CFBundleIconFiles</key>\r\n\t      " +
		"<array>\r\n\t        <string>\r\n\t          Icon.png</string>\r\n\t        <string>\r\n\t          " +
		"Icon@2x.png</string>\r\n\t        <string>\r\n\t          Icon@3x.png</string>\r\n\t        </array>\r\n\t      " +
		"<key>\r\n\t        CFBundleIcons</key>\r\n\t      <dict>\r\n\t        <key>\r\n\t          " +
		"CFBundlePrimaryIcon</key>\r\n\t        <dict>\r\n\t          <key>\r\n\t            " +
		"CFBundleIconFiles</key>\r\n\t          <array>\r\n\t            <string>\r\n\t              " +
		"Icon.png</string>\r\n\t            <string>\r\n\t              Icon@2x.png</string>\r\n\t            " +
		"<string>\r\n\t              Icon@3x.png</string>\r\n\t            </array>\r\n\t          <key>\r\n\t            " +
		"UIPrerenderedIcon</key>\r\n\t          <string>\r\n\t            true</string>\r\n\t          </dict>\r\n\t        " +
		"</dict>\r\n\t      <key>\r\n\t        CFBundleIdentifier</key>\r\n\t      <string>\r\n\t        " +
		"org.h6nry.moresettings</string>\r\n\t      <key>\r\n\t        CFBundleInfoDictionaryVersion</key>\r\n\t      " +
		"<string>\r\n\t        6.0</string>\r\n\t      <key>\r\n\t        CFBundlePackageType</key>\r\n\t      " +
		"<string>\r\n\t        APPL</string>\r\n\t      <key>\r\n\t        CFBundleSignature</key>\r\n\t      " +
		"<string>\r\n\t        ????</string>\r\n\t      <key>\r\n\t        CFBundleSupportedPlatforms</key>\r\n\t      " +
		"</dict>\r\n\t    </plist>\r\n\t  \n", FormatXML(plistExample, "\t", "  "))
}

