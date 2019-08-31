package services

import (
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestVirusTotalAdapter(t *testing.T) {
	mainFolder, _ := utils.FindMainFolder()
	assert.NoError(t, godotenv.Load(mainFolder+string(os.PathSeparator)+".env"))
	apiKey := os.Getenv("VIRUS_TOTAL_API_KEY")
	assert.NotEmpty(t, apiKey)
	path, _ := utils.FindTest("apps", "binary.ipa")
	var (
		command = utils.Command{VirusTotalKey: apiKey, Path: path}
		entity  entities.VirusAnalysis
	)
	assert.NoError(t, VirusTotalAdapter(command, &entity))
	assert.Equal(t,
		"Scan finished, information embedded",
		entity.Response.VerboseMsg, "wrong api response")
}
