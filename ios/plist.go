package ios

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	plistlib "github.com/groob/plist"
)

// types

type CFBundleURLType struct {
	CFBundleURLName string
	CFBundleURLSchemes []string
}

// PList

type PListPermission struct {
	Name string
	Description string
	Reason string
}

type PListInsecureConnections struct {
	Domains []string
	AllowArbitraryLoads bool
}

type PList struct {
	BinName string
	Bin string
	Id string
	Version string
	Build string
	SDK string
	Platform string
	Min string
	PListXML string
	Permissions []PListPermission
	InsecureConnections PListInsecureConnections
	BundleName string
	BundleVersionName string
	BundleUrlTypes []CFBundleURLType
	BundleSupportedPlatforms []string
	BundleLocalizations []string
}

// NSAppTransportSecurityObject

type NSExceptionDomain struct {
	NSIncludesSubdomains bool
	NSTemporaryExceptionAllowsInsecureHTTPLoads bool
	NSTemporaryExceptionMinimumTLSVersion string
}

type NSExceptionDomains map[string]NSExceptionDomain

type NSAppTransportSecurityObject struct {
	NSAllowsArbitraryLoads bool
	NSExceptionDomains NSExceptionDomains
}

// PListObject

type PListObject struct {
	CFBundleDisplayName string
	CFBundleExecutable string
	CFBundleIdentifier string
	CFBundleVersion string
	DTSDKName string
	DTPlatformVersion string
	MinimumOSVersion string
	CFBundleName string
	CFBundleShortVersionString string
	CFBundleURLTypes []CFBundleURLType
	CFBundleSupportedPlatforms []string
	CFBundleLocalizations []string
	NSAppleMusicUsageDescription string
	NSBluetoothPeripheralUsageDescription string
	NSCalendarsUsageDescription string
	NSCameraUsageDescription string
	NSContactsUsageDescription string
	NSHealthShareUsageDescription string
	NSHealthUpdateUsageDescription string
	NSHomeKitUsageDescription string
	NSLocationAlwaysUsageDescription string
	NSLocationUsageDescription string
	NSLocationWhenInUseUsageDescription string
	NSMicrophoneUsageDescription string
	NSMotionUsageDescription string
	NSPhotoLibraryUsageDescription string
	NSRemindersUsageDescription string
	NSVideoSubscriberAccountUsageDescription string
	NSAppTransportSecurity NSAppTransportSecurityObject
}

func findPListFile(src string, isSrc bool) (string, string, error) {
	var appname string
	var pListFile string
	if isSrc {
		files, err := ioutil.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xcodeproj") {
				_, appname = filepath.Split(f.Name())
				appname = strings.Replace(appname, ".xcodeproj", "", 1)
			}
		}
		err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if !strings.Contains(path, "__MACOSX") && strings.HasSuffix(info.Name(), "Info.plist") {
				pListFile = path
			}
			if err != nil {
				return err
			}
			return nil
		})
	} else {
		files, err := ioutil.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".app") {
				appname = f.Name()
				break
			}
		}
		pListFile = filepath.Join(filepath.Join(src, appname), "Info.plist")
	}
	if _, err := os.Stat(pListFile); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cannot find Info.plist file. Skipping PList Analysis")
	}
	return pListFile, appname, nil
}

func makePListAnalysis(pListFile, appName string, isSrc bool) (*PList, error) {
	var plistObject PListObject
	var plist = &PList{}
	dat, err := ioutil.ReadFile(pListFile)
	if err != nil {
		return nil, fmt.Errorf("error opening Info.plist file. Skipping PList Analysis")
	}
	err = plistlib.Unmarshal(dat, &plistObject)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling Info.plist file with error %s. Skipping PList Analysis", err)
	}
	xmlBytes, err := plistlib.MarshalIndent(plistObject, "\t")
	if err != nil {
		log.Println(err)
		plist.PListXML = "error"
	} else {
		plist.PListXML = string(xmlBytes)
	}
	plist.BinName = plistObject.CFBundleDisplayName
	if plist.BinName == "" && !isSrc {
		plist.BinName = strings.Replace(appName, ".app", "", 1)
	}
	plist.Bin = plistObject.CFBundleExecutable
	plist.Id = plistObject.CFBundleIdentifier
	plist.Build = plistObject.CFBundleVersion
	plist.SDK = plistObject.DTSDKName
	plist.Platform = plistObject.DTPlatformVersion
	plist.Min = plistObject.MinimumOSVersion
	plist.BundleName = plistObject.CFBundleName
	plist.BundleVersionName = plistObject.CFBundleVersion
	plist.BundleUrlTypes = plistObject.CFBundleURLTypes
	plist.BundleSupportedPlatforms = plistObject.CFBundleSupportedPlatforms
	plist.BundleLocalizations = plistObject.CFBundleLocalizations
	plist.Permissions = checkPermissions(&plistObject)
	plist.InsecureConnections = checkInsecureConnections(&plistObject)
	return plist, nil
}

func PListAnalysis(src string, isSrc bool) (*PList, error) {
	pListFile, appName, err := findPListFile(src, isSrc)
	if err != nil {
		return nil, err
	}
	return makePListAnalysis(pListFile, appName, isSrc)
}

func checkPermissions(plistObj *PListObject) []PListPermission {
	var list []PListPermission
	for k, v := range map[interface{}]PListPermission{
		plistObj.NSAppleMusicUsageDescription: {
			Name:        "NSAppleMusicUsageDescription",
			Description: "Access Apple Media Library.",
			Reason:      plistObj.NSAppleMusicUsageDescription,
		},
		plistObj.NSBluetoothPeripheralUsageDescription : {
			Name:        "NSBluetoothPeripheralUsageDescription",
			Description: "Access Bluetooth Interface.",
			Reason:      plistObj.NSBluetoothPeripheralUsageDescription,
		},
		plistObj.NSCalendarsUsageDescription : {
			Name: 		 "NSCalendarsUsageDescription",
			Description: "Access Calendars.",
			Reason: 	 plistObj.NSCalendarsUsageDescription,
		},
		plistObj.NSCameraUsageDescription : {
			Name: 		 "NSCameraUsageDescription",
			Description: "Access the Camera.",
			Reason: 	 plistObj.NSCameraUsageDescription,
		},
		plistObj.NSContactsUsageDescription : {
			Name: "NSContactsUsageDescription",
			Description: "Access Contacts.",
			Reason: plistObj.NSContactsUsageDescription,
		},
		plistObj.NSHealthShareUsageDescription : {
			Name: "NSHealthShareUsageDescription",
			Description: "Read Health Data.",
			Reason: plistObj.NSHealthShareUsageDescription,
		},
		plistObj.NSHealthUpdateUsageDescription : {
			Name: "NSHealthUpdateUsageDescription",
			Description: "Write Health Data.",
			Reason: plistObj.NSHealthUpdateUsageDescription,
		},
		plistObj.NSHomeKitUsageDescription : {
			Name: "NSHomeKitUsageDescription",
			Description: "Access HomeKit configuration data.",
			Reason: plistObj.NSHomeKitUsageDescription,
		},
		plistObj.NSLocationAlwaysUsageDescription : {
			Name: "NSLocationAlwaysUsageDescription",
			Description: "Access location information at all times.",
			Reason: plistObj.NSLocationAlwaysUsageDescription,
		},
		plistObj.NSLocationUsageDescription : {
			Name: "NSLocationUsageDescription",
			Description: "Access location information at all times (< iOS 8).",
			Reason: plistObj.NSLocationUsageDescription,
		},
		plistObj.NSLocationWhenInUseUsageDescription : {
			Name: "NSLocationWhenInUseUsageDescription",
			Description: "Access location information when app is in the foreground.",
			Reason: plistObj.NSLocationWhenInUseUsageDescription,
		},
		plistObj.NSMicrophoneUsageDescription : {
			Name: "NSMicrophoneUsageDescription",
			Description: "Access microphone.",
			Reason: plistObj.NSMicrophoneUsageDescription,
		},
		plistObj.NSMotionUsageDescription : {
			Name: "NSMotionUsageDescription",
			Description: "Access the device’s accelerometer.",
			Reason: plistObj.NSMotionUsageDescription,
		},
		plistObj.NSPhotoLibraryUsageDescription : {
			Name: "NSPhotoLibraryUsageDescription",
			Description: "Access the user’s photo library.",
			Reason: plistObj.NSPhotoLibraryUsageDescription,
		},
		plistObj.NSRemindersUsageDescription : {
			Name: "NSRemindersUsageDescription",
			Description: "Access the user’s reminders.",
			Reason: plistObj.NSRemindersUsageDescription,
		},
		plistObj.NSVideoSubscriberAccountUsageDescription : {
			Name: "NSVideoSubscriberAccountUsageDescription",
			Description: "Access the user’s TV provider account.",
			Reason: plistObj.NSVideoSubscriberAccountUsageDescription,
		},
	} {
		if k != "" {
			list = append(list, v)
		}
	}
	return list
}

func checkInsecureConnections(plistObj *PListObject) PListInsecureConnections {
	var insecureConnections PListInsecureConnections
	insecureConnections.AllowArbitraryLoads = plistObj.NSAppTransportSecurity.NSAllowsArbitraryLoads
	for k := range plistObj.NSAppTransportSecurity.NSExceptionDomains {
		insecureConnections.Domains = append(insecureConnections.Domains, k)
	}
	return insecureConnections
}