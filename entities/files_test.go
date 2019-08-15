package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	fileAnalysisTestMap = map[string]interface{}{
		"certifications":[]string{},
		"databases":[]string{},
		"files":[]string{"/README.md", "/iVim", "/iVim/ArgumentToken.swift", "/iVim/Assets.xcassets",
			"/iVim/Assets.xcassets/AppIcon.appiconset", "/iVim/Assets.xcassets/AppIcon.appiconset/Contents.json",
		},
		"plists":[]string{"/iVim/Info.plist", "/iVim/Settings.bundle/Root.plist", "/iVim/systemFonts.plist",
			"/iVim.xcodeproj/project.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist",
		},
	}

	wrongFileAnalysisTestMap = map[string]interface{}{
		"certs":[]string{},
		"plist":[]string{"/iVim/Info.plist", "/iVim/Settings.bundle/Root.plist", "/iVim/systemFonts.plist",
			"/iVim.xcodeproj/project.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist",
		},
	}
)



func TestFileAnalysisMapTransformation(t *testing.T) {
	p, err := (&FileAnalysis{}).FromMap(fileAnalysisTestMap)
	assert.NoError(t, err)
	assert.Equal(t, fileAnalysisTestMap, p.ToMap())
}

func TestFileAnalysisValidation(t *testing.T) {
	p, err := (&FileAnalysis{}).FromMap(fileAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&FileAnalysis{}).FromMap(wrongFileAnalysisTestMap)
	t.Logf("%#v", p)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 4)
}

