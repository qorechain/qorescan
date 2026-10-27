// SPDX-License-Identifier: Apache-2.0

package nodehome

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// tomlValue is one key of a node configuration file with the line it is on.
type tomlValue struct {
	Raw  string
	Line int
}

// String returns the value as a string: TOML strings are unquoted, other
// values are returned as written.
func (v tomlValue) String() string {
	r := v.Raw
	if len(r) >= 2 && r[0] == '"' && r[len(r)-1] == '"' {
		if s, err := strconv.Unquote(r); err == nil {
			return s
		}
		return r[1 : len(r)-1]
	}
	if len(r) >= 2 && r[0] == '\'' && r[len(r)-1] == '\'' {
		return r[1 : len(r)-1]
	}
	return r
}

// Bool reports whether the value is the TOML literal true.
func (v tomlValue) Bool() bool { return strings.TrimSpace(v.Raw) == "true" }

// tomlDoc maps "section.key" (or "key" at top level) to its value.
type tomlDoc map[string]tomlValue

// parseTOML reads the flat subset of TOML that node configuration files use:
// [section] headers, key = value lines, comments and arrays (kept raw, may
// span lines). It keeps line numbers, which a full TOML decoder does not
// expose, so evidence can point at the exact line.
func parseTOML(data []byte) tomlDoc {
	doc := tomlDoc{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	line := 0
	var pendingKey string
	var pending strings.Builder
	pendingLine := 0
	depth := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if pendingKey != "" {
			clean := stripComment(text)
			pending.WriteString(" " + strings.TrimSpace(clean))
			depth += strings.Count(clean, "[") - strings.Count(clean, "]")
			if depth <= 0 {
				doc[pendingKey] = tomlValue{Raw: strings.TrimSpace(pending.String()), Line: pendingLine}
				pendingKey = ""
				pending.Reset()
			}
			continue
		}
		t := strings.TrimSpace(stripComment(text))
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[] ")
			continue
		}
		eq := strings.Index(t, "=")
		if eq <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(t[:eq]), `"`)
		val := strings.TrimSpace(t[eq+1:])
		full := key
		if section != "" {
			full = section + "." + key
		}
		if strings.HasPrefix(val, "[") {
			d := strings.Count(val, "[") - strings.Count(val, "]")
			if d > 0 {
				pendingKey, pendingLine, depth = full, line, d
				pending.WriteString(val)
				continue
			}
		}
		doc[full] = tomlValue{Raw: val, Line: line}
	}
	return doc
}

// stripComment removes a # comment that is not inside a string.
func stripComment(s string) string {
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr != 0:
			if c == '\\' && inStr == '"' {
				i++
			} else if c == inStr {
				inStr = 0
			}
		case c == '"' || c == '\'':
			inStr = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}
