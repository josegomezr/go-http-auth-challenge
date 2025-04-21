// A compliant-enough implementation to parse HTTP WWW-Authenticate & Authorization headers
package http_auth

import (
	"errors"
	"github.com/josegomezr/go-http-auth-challenge/internal/tokenizer"
	"strconv"
	"strings"
)

func parseHeader(header string, strict bool) []Challenge {
	ret := []Challenge{}
	currentChallenge := Challenge{}
	header = strings.TrimSpace(header)

	for token := range tokenizer.Tokenize(header) {
		if token.Type == tokenizer.TokenToken {
			if !currentChallenge.IsEmpty() {
				ret = append(ret, currentChallenge)
				currentChallenge = Challenge{}
			}
			currentChallenge.Scheme = token.Value
		}

		if token.Type == tokenizer.TokenAuthParam {
			key, val, _ := strings.Cut(token.Value, "=")
			unquoted, err := strconv.Unquote(val)
			if err == nil {
				val = unquoted
			}
			currentChallenge.setParam(key, val)
		}

		if token.Type == tokenizer.TokenToken68 {
			if len(currentChallenge.Params) > 0 {
				ret = append(ret, currentChallenge)
				currentChallenge = Challenge{}
				currentChallenge.Scheme = token.Value
			} else {
				currentChallenge.addPositionalParam(token.Value)
			}
		}
	}
	ret = append(ret, currentChallenge)
	return ret
}

// ParseChallenges returns a list of [Challenge]'s found.
func ParseChallenges(header string, strict bool) ([]Challenge, error) {
	challenges := parseHeader(header, strict)
	challengeCount := len(challenges)
	if challengeCount == 0 {
		return nil, errors.New("no challenges could be parsed")
	}

	currentChallenge := challenges[challengeCount-1]

	if currentChallenge.IsEmpty() {
		if strict {
			return challenges, errors.New("incomplete header")
		}
		challenges = challenges[:challengeCount-1]
	}

	return challenges, nil
}

// ParseAuthorization returns a list of [Challenge]'s found.
func ParseAuthorization(header string, strict bool) (Authorization, error) {
	challenges := parseHeader(header, strict)
	challengeCount := len(challenges)
	if challengeCount == 0 {
		return Authorization{}, errors.New("no challenges could be parsed")
	}

	if challengeCount > 1 {
		return Authorization{}, errors.New("More than one authorization was provided in the same header")
	}

	return challenges[0], nil
}
