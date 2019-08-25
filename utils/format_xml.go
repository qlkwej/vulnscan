// Taken from https://github.com/go-xmlfmt/xmlfmt
// Created by Antonio Sun based on http://www.perlmonks.org/?node_id=261292
// MIT license
// The project doesn't seem to be active and doesn't seem reasonable to add an extra dependency
// for this, so we include it directly on our code

package utils

import (
	"regexp"
	"strings"
)

var reg = regexp.MustCompile(`<([/!]?)([^>]+?)(/?)>`)

// FormatXML will reformat the XML string in a readable way, without any rewriting/altering the structure
func FormatXML(xmls, prefix, indent string) string {
	src := regexp.MustCompile(`>\s+<`).ReplaceAllString(xmls, "><")
	rf := replaceTag(prefix, indent)
	return prefix + reg.ReplaceAllStringFunc(src, rf)
}

// replaceTag returns a closure function to do
// 's/(?<=>)\s+(?=<)//g; s(<(/?)([^>]+?)(/?)>)($indent+=$3?0:$1?-1:1;"<$1$2$3>"."\n".("  "x$indent))ge' as in Perl
// and deal with comments as well
func replaceTag(prefix, indent string) func(string) string {
	indentLevel := 0
	return func(m string) string {
		parts := reg.FindStringSubmatch(m)
		// $3: A <foo/> tag. No alteration to indentation.
		// $1: A closing </foo> tag. Drop one indentation level
		// else: An opening <foo> tag. Increase one indentation level
		if len(parts[3]) == 0 {
			if parts[1] == `/` {
				indentLevel -= 1
			} else if parts[1] != `!` {
				indentLevel += 1
			}
		}
		return "<" + parts[1] + parts[2] + parts[3] + ">" +
			"\r\n" + prefix + strings.Repeat(indent, indentLevel)
	}
}

