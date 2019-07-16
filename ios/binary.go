package ios

import (
	"runtime"

	"github.com/kardianos/osext"
)

type CommandType int

const (
	Libs CommandType = iota
	Header
)

func getOtoolOut(binPath string, ct CommandType) {
	platform := runtime.GOOS
	var args []string
	if ct == Libs {
		if platform == "darwin" {
			args = []string{"otool", "-L", binPath}
		} else if platform == "linux" {

		}
	} else {

	}
}
