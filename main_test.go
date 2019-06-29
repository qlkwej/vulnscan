package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/urfave/cli.v1"
)

// Helper function to get rid from spaces comparing strings
func stripSpaces(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

type opCounts struct {
	Total, BashComplete, OnUsageError, Before, CommandNotFound, Action, After, SubCommand int
}

func TestCommandsHelp(t *testing.T) {
	counts := &opCounts{}

	resetCounts := func() { counts = &opCounts{} }

	a := getApp()

	a.CommandNotFound = func(c *cli.Context, command string) {
		counts.Total++
		counts.CommandNotFound = counts.Total
	}

	a.Commands = []cli.Command{
		{
			Name: "lookup",
			Action: func(c *cli.Context) error {
				counts.Total++
				counts.SubCommand = counts.Total
				return nil
			},
		},
		{
			Name: "scan",
			Action: func(c *cli.Context) error {
				counts.Total++
				counts.SubCommand = counts.Total
				return nil
			},
		},
	}

	a.Run([]string{"command", "lookup"})
	expect(t, counts.CommandNotFound, 0)
	expect(t, counts.SubCommand, 1)
	expect(t, counts.Total, 1)

	resetCounts()

	a.Run([]string{"command", "scan"})
	expect(t, counts.CommandNotFound, 0)
	expect(t, counts.SubCommand, 1)
	expect(t, counts.Total, 1)

	resetCounts()
	a.Run([]string{"command", "foo"})
	expect(t, counts.CommandNotFound, 1)
	expect(t, counts.SubCommand, 0)
	expect(t, counts.Total, 1)
}

func TestPrintItunesResults(t *testing.T) {
	r, w, _ := os.Pipe()
	log.SetOutput(w)
	// Use a goroutine so printing can't block indefinitely
	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()
	printiTunesResults("com.easilydo.mail", "us")
	_ = w.Close()
	log.SetOutput(os.Stdout)
	out := <-outC
	var messages strings.Builder
	for _, sps := range strings.Split(out, "\n") {
		if len(sps) > 1 {
			messages.WriteString(strings.Join(strings.Split(sps, " ")[2:], " "))
			messages.WriteString(" ")
		}
	}
	if msg, testMsg := messages.String(),
		"Fetching Details from App Store: com.easilydo.mail Total Results: 1 Title: "+
			"Email - Edison Mail URL: https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4"; stripSpaces(msg) != stripSpaces(testMsg) {
		t.Errorf("Error printing itunes result, expected: %s, got: %s", testMsg, msg)
	}
}
