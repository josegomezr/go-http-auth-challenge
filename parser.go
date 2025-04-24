// A compliant-enough implementation to parse HTTP WWW-Authenticate & Authorization headers
package http_auth

import (
	"fmt"
	"iter"
	"strconv"
	"strings"
)

func ChallengesIterator(input string) iter.Seq2[Challenge, error] {
	return func(yield func(Challenge, error) bool) {
		curr := NewChallenge()
		for chunk := range groupTokensUntilComma(tokenize(input)) {
			scheme, value, err := processChunk(chunk...)
			if err != nil {
				yield(curr, fmt.Errorf("Error processing header: %+w", err))
				return
			}

			if len(scheme) > 0 {
				if curr.Scheme != "" {
					if !yield(curr, nil) {
						return
					}
					curr = NewChallenge()
				}
				curr.Scheme = scheme
			}

			if len(value) > 0 {
				if curr.Scheme == "" {
					yield(curr, fmt.Errorf("Unexpected param before scheme"))
					return
				}

				pos := strings.IndexRune(value, '=')
				if pos < 0 || pos == len(value)-1 {
					curr.setTokenParam(value)
				} else {
					key, val, _ := strings.Cut(value, "=")
					unquoted, err := strconv.Unquote(val)
					if err == nil {
						val = unquoted
					}
					curr.setParam(key, val)
				}
			}
		}
		if curr.Scheme != "" {
			yield(curr, nil)
		}
	}
}

func ParseChallenges(input string) ([]Challenge, error) {
	var res []Challenge
	for challenge, err := range ChallengesIterator(input) {
		if err != nil {
			return nil, err
		}
		res = append(res, challenge)
	}

	if len(res) <= 0 {
		return nil, fmt.Errorf("Empty challenges")
	}
	return res, nil
}

func ParseAuthorization(input string) (Authorization, error) {
	next, stop := iter.Pull2(ChallengesIterator(input))
	defer stop()
	challenge, err, ok := next()
	if !ok {
		return challenge, fmt.Errorf("No auth header found")
	}
	if err != nil {
		return challenge, err
	}

	_, err, ok = next()
	if ok {
		return challenge, fmt.Errorf("multiple auth scheme found in a single header")
	}

	return challenge, nil
}

func processChunk(chunk ...string) (scheme string, value string, err error) {
	switch len(chunk) {
	case 1:
		// Receiving a single element
		tok := chunk[0]

		if tok == "," {
			// This is the case of a redundant comma
			return
		} else if strings.ContainsRune(tok, '=') {
			value = tok
		} else {
			scheme = tok
		}
	case 2:
		scheme, value = chunk[0], chunk[1]
		if len(scheme) == 0 || len(value) == 0 {
			err = fmt.Errorf("empty scheme/value")
		} else if value == "," {
			value = scheme
			scheme = ""
		}
	case 3:
		scheme, value = chunk[0], chunk[1]
		if len(scheme) == 0 || len(value) == 0 {
			err = fmt.Errorf("empty scheme/value")
		}
	default:
		err = fmt.Errorf("Redundant syntax: %d-%+v", len(chunk), chunk)
	}
	return
}
