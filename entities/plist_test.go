package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	bundleUrlTypeTestMap = map[string]interface{}{
		"name": "com.terrychou.vim",
		"schemas": []string{"ivimeditor"},
	}
	wrongBundleUrlTypeTestMap = map[string]interface{}{
		"schemas": []string{},
	}
	permissionTestMap = map[string]interface{}{
		"name":        "NSMicrophoneUsageDescription",
		"description": "Access microphone.",
		"reason":      "Reason",
	}
	wrongPermissionTestMap = map[string]interface{}{
		"name":        "",
		"description": "",
		"reason":      "",
	}
	insecureConnectionsTestMap = map[string]interface{}{
		"allow_arbitrary_loads": false,
		"domains": []string{},

	}
	plistAnalysisTestMap = map[string]interface{}{
		"xml":"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
			"\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n\t<dict>\n\t\t" +
			"<key>CFBundleDisplayName</key>\n\t\t<string></string>\n\t\t<key>CFBundleExecutable</key>\n\t\t" +
			"<string>iVim</string>\n\t\t<key>CFBundleIdentifier</key>\n\t\t<string>com.terrychou.ivim</string>\n\t\t" +
			"<key>CFBundleLocalizations</key>\n\t\t<array></array>\n\t\t<key>CFBundleName</key>\n\t\t" +
			"<string>iVim</string>\n\t\t<key>CFBundleShortVersionString</key>\n\t\t<string>1.40</string>\n\t\t" +
			"<key>CFBundleSupportedPlatforms</key>\n\t\t<array>\n\t\t\t<string>iPhoneSimulator</string>\n\t\t" +
			"</array>\n\t\t<key>CFBundleURLTypes</key>\n\t\t<array>\n\t\t\t<dict>\n\t\t\t\t" +
			"<key>CFBundleURLName</key>\n\t\t\t\t<string>com.terrychou.vim</string>\n\t\t\t\t" +
			"<key>CFBundleURLSchemes</key>\n\t\t\t\t<array>\n\t\t\t\t\t<string>ivimeditor</string>\n\t\t\t\t" +
			"</array>\n\t\t\t</dict>\n\t\t</array>\n\t\t<key>CFBundleVersion</key>\n\t\t<string>1</string>\n\t\t" +
			"<key>DTPlatformVersion</key>\n\t\t<string>12.1</string>\n\t\t<key>DTSDKName</key>\n\t\t" +
			"<string>iphonesimulator12.1</string>\n\t\t<key>MinimumOSVersion</key>\n\t\t<string>9.1</string>\n\t\t" +
			"<key>NSAppTransportSecurity</key>\n\t\t<dict>\n\t\t\t<key>NSAllowsArbitraryLoads</key><false/>\n\t\t\t" +
			"<key>NSExceptionDomains</key>\n\t\t\t<dict></dict>\n\t\t</dict>\n\t\t" +
			"<key>NSAppleMusicUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSBluetoothPeripheralUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSCalendarsUsageDescription</key>\n\t\t<string></string>\n\t\t<key>NSCameraUsageDescription</key>\n\t\t" +
			"<string></string>\n\t\t<key>NSContactsUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHealthShareUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHealthUpdateUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHomeKitUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationAlwaysUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationWhenInUseUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSMicrophoneUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSMotionUsageDescription</key>\n\t\t<string></string>\n\t\t<key>NSPhotoLibraryUsageDescription</key>\n\t\t" +
			"<string></string>\n\t\t<key>NSRemindersUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSVideoSubscriberAccountUsageDescription</key>\n\t\t<string></string>\n\t</dict>\n</plist>\n",
		"bin":"iVim",
		"bin_name":"iVim",
		"id":"com.terrychou.ivim",
		"build":"1",
		"sdk":"iphonesimulator12.1",
		"platform":"12.1",
		"minimum_version":"9.1",
		"bundle_name":"iVim",
		"bundle_version_name":"1",
		"bundle_supported_platforms":[]string{"iPhoneSimulator"},
		"bundle_localizations": []string{"es"},
		"bundle_url_types":[]map[string]interface {}{
			{"name": "com.terrychou.vim", "schemas": []string{"ivimeditor"}},
		},
		"insecure_connections":map[string]interface {}{
			"allow_arbitrary_loads":false,
			"domains":[]string{},
		},
		"permissions": []map[string]interface{}{
			{
				"name":        "NSMicrophoneUsageDescription",
				"description": "Access microphone.",
				"reason":      "Reason",
			},
		},
	}
	wrongPlistAnalysisTestMap = map[string]interface{}{
		"id":"com.terrychou.ivim",
		"build":"1",
		"sdk":"iphonesimulator12.1",
		"platform":"12.1",
		"minimum_version":"9.1",
		"bundle_name":"iVim",
		"bundle_version_name":"1",
		"bundle_supported_platforms":[]string{"iPhoneSimulator"},
		"bundle_localizations": []string{"es"},
		"insecure_connections":map[string]interface {}{
			"allow_arbitrary_loads":false,
			"domains":[]string{},
		},
	}
)


func TestBundleUrlTypeMapTransformation(t *testing.T) {
	p, err := (&BundleUrlType{}).FromMap(bundleUrlTypeTestMap)
	assert.NoError(t, err)
	assert.Equal(t, bundleUrlTypeTestMap, p.ToMap())
}

func TestBundleUrlTypesValidation(t *testing.T) {
	p, err := (&BundleUrlType{}).FromMap(bundleUrlTypeTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&BundleUrlType{}).FromMap(wrongBundleUrlTypeTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}


func TestPermissionMapTransformation(t *testing.T) {
	p, err := (&Permission{}).FromMap(permissionTestMap)
	assert.NoError(t, err)
	assert.Equal(t, permissionTestMap, p.ToMap())
}

func TestPermissionValidation(t *testing.T) {
	p, err := (&Permission{}).FromMap(permissionTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&Permission{}).FromMap(wrongPermissionTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 3)
}

func TestInsecureConnectionsTransformation(t *testing.T) {
	p, err := (&InsecureConnections{}).FromMap(insecureConnectionsTestMap)
	assert.NoError(t, err)
	assert.Equal(t, insecureConnectionsTestMap, p.ToMap())
}


func TestPlistAnalysisTransformation(t *testing.T) {
	p, err := (&PListAnalysis{}).FromMap(plistAnalysisTestMap)
	assert.NoError(t, err)
	assert.Equal(t, plistAnalysisTestMap, p.ToMap())
}

func TestPlistAnalysisValidation(t *testing.T) {
	p, err := (&PListAnalysis{}).FromMap(plistAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&PListAnalysis{}).FromMap(wrongPlistAnalysisTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 5)
}

