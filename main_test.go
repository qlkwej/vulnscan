package main

import (
	"github.com/simplycubed/vulnscan/utils"
	"gopkg.in/urfave/cli.v1"
	"testing"
)

type opCounts struct {
	Total, BashComplete, OnUsageError, Before, CommandNotFound, Action, After, SubCommand int
}

func TestCommands(t *testing.T) {
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

	err := a.Run([]string{"command", "lookup"})
	if err != nil {
		t.Error(err)
	}
	utils.Expect(t, counts.CommandNotFound, 0)
	utils.Expect(t, counts.SubCommand, 1)
	utils.Expect(t, counts.Total, 1)
	resetCounts()

	err = a.Run([]string{"command", "scan"})
	if err != nil {
		t.Error(err)
	}
	utils.Expect(t, counts.CommandNotFound, 0)
	utils.Expect(t, counts.SubCommand, 1)
	utils.Expect(t, counts.Total, 1)
	resetCounts()

	err = a.Run([]string{"command", "foo"})
	if err != nil {
		t.Error(err)
	}
	utils.Expect(t, counts.CommandNotFound, 1)
	utils.Expect(t, counts.SubCommand, 0)
	utils.Expect(t, counts.Total, 1)
}

