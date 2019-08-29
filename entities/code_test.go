package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	apiFindingTestMap = map[string]interface{}{
		"description": "Encryption API",
		"paths": []string{
			"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
			"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
			"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
		},
	}
	wrongApiFindingTestMap = map[string]interface{}{
		"descriptio": "Encryption API",
		"paths":      []string{},
	}
	codeFindingTestMap = map[string]interface{}{
		"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
		"cvss":        7.4,
		"cwe":         "CWE-312",
		"level":       "High",
		"paths": []string{
			"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
			"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
			"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
			"/YapDatabase/YapDatabaseConnection.m",
		},
	}
	wrongCodeFindingTestMap = map[string]interface{}{
		"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
		"cvss":        7.4,
		"cwe":         "312",
		"level":       "Low",
		"paths":       []string{},
	}
	urlFindingTestMap = map[string]interface{}{
		"url": "http://code.google.com",
		"paths": []string{
			"/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m",
			"/YapDatabase/Utilities/YapMurmurHash.m",
		},
	}
	wrongUrlFindingTestMap = map[string]interface{}{
		"url":   "",
		"paths": []string{},
	}
	emailFindingTestMap = map[string]interface{}{
		"email": "bar@example.com",
		"paths": []string{"/View Controllers/SolutionsViewController.m"},
	}
	wrongEmailFindingTestMap = map[string]interface{}{
		"email": "",
		"paths": []string{},
	}
	codeAnalysisTestMap = map[string]interface{}{
		"codes": []map[string]interface{}{
			{
				"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
				"cvss":        7.4,
				"cwe":         "CWE-312",
				"level":       "High",
				"paths": []string{
					"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
					"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
					"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
					"/YapDatabase/YapDatabaseConnection.m",
				},
			},
			{
				"description": "IP Address disclosure",
				"cvss":        4.3,
				"cwe":         "CWE-200",
				"level":       "Info",
				"paths":       []string{"/YapDatabase/YapDatabase.m"},
			},
		},
		"apis": []map[string]interface{}{
			{
				"description": "Encryption API",
				"paths": []string{
					"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
					"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
					"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
				},
			},
		},
		"urls": []map[string]interface{}{
			{
				"url":   "http://code.google.com",
				"paths": []string{"/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m"},
			},
			{
				"url":   "http://en.wikipedia.org",
				"paths": []string{"/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m"},
			},
			{
				"url": "http://enriquez.me",
				"paths": []string{
					"/Third Party Classes/ECSlidingViewController/ECPercentDrivenInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingAnimationController.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingSegue.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingViewController.m",
					"/Third Party Classes/ECSlidingViewController/UIViewControllerxECSlidingViewController.m",
				},
			},
		},
		"emails": []map[string]interface{}{
			{
				"email": "bar@example.com",
				"paths": []string{"/View Controllers/SolutionsViewController.m"},
			},
			{
				"email": "damien.bergamini@free.fr",
				"paths": []string{"/Third Party Classes/RNCryptor/RNCryptor.m"},
			},
			{
				"email": "foo@example.com",
				"paths": []string{"/View Controllers/SolutionsViewController.m"},
			},
		},
		"bad_domains": []string{"dangeroussitetovisit.com"},
	}
	wrongCodeAnalysisTestMap = map[string]interface{}{
		"codes": []map[string]interface{}{
			{
				"description": "Encryption API",
				"paths": []string{
					"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
					"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
					"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
				},
			},
		},
		"apis": []map[string]interface{}{
			{
				"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
				"cvss":        7.4,
				"cws":         "CWE-312",
				"level":       "High",
				"paths": []string{
					"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
					"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
					"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
					"/YapDatabase/YapDatabaseConnection.m",
				},
			},
		},
		"urls": []map[string]interface{}{
			{
				"email": "bar@example.com",
				"paths": []string{"/View Controllers/SolutionsViewController.m"},
			},
			{
				"email": "damien.bergamini@free.fr",
				"paths": []string{"/Third Party Classes/RNCryptor/RNCryptor.m"},
			},
			{
				"email": "foo@example.com",
				"paths": []string{"/View Controllers/SolutionsViewController.m"},
			},
		},
		"emails": []map[string]interface{}{
			{
				"url":   "http://code.google.com",
				"paths": []string{"/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m"},
			},
			{
				"url":   "http://en.wikipedia.org",
				"paths": []string{"/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m"},
			},
			{
				"url": "http://enriquez.me",
				"paths": []string{
					"/Third Party Classes/ECSlidingViewController/ECPercentDrivenInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingAnimationController.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingSegue.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingViewController.m",
					"/Third Party Classes/ECSlidingViewController/UIViewControllerxECSlidingViewController.m",
				},
			},
		},
	}
)

func TestApiFindiingMapTransformation(t *testing.T) {
	af := &ApiFinding{}
	p, err := af.FromMap(apiFindingTestMap)
	assert.NoError(t, err)
	assert.Equal(t, p.ToMap(), apiFindingTestMap)
}

func TestApiFindingValidation(t *testing.T) {
	af := &ApiFinding{}
	p, err := af.FromMap(apiFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = af.FromMap(wrongApiFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}

func TestCodeFindingMapTransformation(t *testing.T) {
	af := &CodeFinding{}
	p, err := af.FromMap(codeFindingTestMap)
	assert.NoError(t, err)
	assert.Equal(t, codeFindingTestMap, p.ToMap())
}

func TestCodeFindingValidation(t *testing.T) {
	af := &CodeFinding{}
	p, err := af.FromMap(codeFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = af.FromMap(wrongCodeFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 3)
}

func TestUrlFindingMapTransformation(t *testing.T) {
	af := &UrlFinding{}
	p, err := af.FromMap(urlFindingTestMap)
	assert.NoError(t, err)
	assert.Equal(t, urlFindingTestMap, p.ToMap())
}

func TestUrlFindingValidation(t *testing.T) {
	af := &UrlFinding{}
	p, err := af.FromMap(urlFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = af.FromMap(wrongUrlFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}

func TestEmailFindingMapTransformation(t *testing.T) {
	af := &EmailFinding{}
	p, err := af.FromMap(emailFindingTestMap)
	assert.NoError(t, err)
	assert.Equal(t, emailFindingTestMap, p.ToMap())
}

func TestEmailFindingValidation(t *testing.T) {
	af := &EmailFinding{}
	p, err := af.FromMap(emailFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = af.FromMap(wrongEmailFindingTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 2)
}

func TestCodeAnalysisMapTransformation(t *testing.T) {
	af := &CodeAnalysis{}
	p, err := af.FromMap(codeAnalysisTestMap)
	assert.NoError(t, err)
	assert.Equal(t, codeAnalysisTestMap, p.ToMap())
}

func TestCodeAnalysisValidation(t *testing.T) {
	af := &CodeAnalysis{}
	p, err := af.FromMap(codeAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = af.FromMap(wrongCodeAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 9)
}
