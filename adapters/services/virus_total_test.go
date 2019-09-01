package services

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/test"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestVirusTotalAdapter(t *testing.T) {
	mainFolder, _ := test.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	apiKey := os.Getenv("VIRUS_TOTAL_API_KEY")
	assert.NotEmpty(t, apiKey)
	path, _ := test.FindTest("adapters", "services", "binary.ipa")
	var (
		command = entities.Command{VirusTotalKey: apiKey, Path: path}
		entity  entities.VirusAnalysis
	)
	assert.NoError(t, VirusTotalAdapter(command, &entity))
	assert.Equal(t,
		"Scan finished, information embedded",
		entity.Response.VerboseMsg, "wrong api response")
}


func TestHashMD5(t *testing.T) {
	file, _ := test.FindTest("adapters", "services", "binary.ipa")
	if hash, e := hashMD5(file); e != nil {
		t.Error(e)
	} else if len(hash) != 32 {
		t.Errorf("Invalid hash length: %d", len(hash))
	}
}
