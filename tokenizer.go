package http_auth

import (
	"bufio"
	"iter"
	"strings"
	"unicode"
	"unicode/utf8"
)

func scanWords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !unicode.IsSpace(r) {
			break
		}
	}
	// Scan until space, marking end of word.
	quoting := false
	escaping := false
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])

		if quoting && escaping {
			escaping = false
			continue
		}

		if r == '"' {
			quoting = !quoting
		}

		if quoting {
			if r == '\\' {
				escaping = true
			}

			continue
		}

		if unicode.IsSpace(r) {
			return i + width, data[start:i], nil
		}

		if r == ',' {
			if i-start == 0 {
				return i + width, data[start : i+width], nil
			}
			return i, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

func tokenize(input string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for group := range groupTokensUntilComma(rawTokenize(input)) {
			group = fixupAssignments(group)
			for _, token := range group {
				if !yield(token) {
					return
				}
			}
		}
	}
}

func fixupAssignments(input []string) []string {
	curr := -1
	ret := []string{}
	equalSignAlone := false
	for _, token := range input {
		if token == "=" {
			equalSignAlone = true
			continue
		}

		if token[0] == '=' {
			prev := ret[curr]
			ret[curr] = prev + token
			continue
		}

		if curr >= 0 {
			if prev := ret[curr]; len(prev) > 0 && prev[len(prev)-1] == '=' {
				ret[curr] += token
				continue
			}
		}

		if equalSignAlone {
			equalSignAlone = false
			prev := ret[curr]
			ret[curr] = prev + "=" + token
			continue
		}

		ret = append(ret, token)
		curr += 1
	}

	return ret
}

// By being _this_ lax we can tolerate certain non-compliances to the HTTP spec,
// like AWS :)
func rawTokenize(input string) iter.Seq[string] {
	scan := bufio.NewScanner(strings.NewReader(input))
	scan.Split(scanWords)

	return func(yield func(string) bool) {
		// prev := ""
		for scan.Scan() {
			t := scan.Text()
			// // A bit ugly to my taste, but allow http list semantics without breaking
			// if prev == "," && t == "," {
			// 	continue
			// }

			// prev = t
			if !yield(t) {
				break
			}
		}
	}
}

func groupTokensUntilComma(seq iter.Seq[string]) iter.Seq[[]string] {
	acc := []string{}

	return func(yield func([]string) bool) {
		next, stop := iter.Pull(seq)
		defer stop()
		for {
			val, ok := next()
			if !ok {
				break
			}
			acc = append(acc, val)
			if val == "," {
				if !yield(acc) {
					return
				}
				acc = []string{}
				continue
			}

		}
		if len(acc) > 0 {
			yield(acc)
		}
	}
}
