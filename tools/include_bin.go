package tools


import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Reads all .txt files in the current folder
// and encodes them as strings literals in textfiles.go
func main() {
	fs, _ := ioutil.ReadDir(".")
	out, _ := os.Create("binaries.go")
	_, _ = out.Write([]byte("package tools \n\nconst (\n"))
	for _, f := range fs {
		_, _ = out.Write([]byte(strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())) + " = `"))
			f, _ := os.Open(f.Name())
		_, _ = io.Copy(out, f)
		_, _ = out.Write([]byte("`\n"))
	}
	_, _ = out.Write([]byte(")\n"))
}
