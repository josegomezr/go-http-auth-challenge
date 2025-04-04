package http_auth

import (
	"errors"
	"strconv"
	"strings"
)

func parseHeader(header string, strict bool) []Challenge {
	ret := []Challenge{}
	currentChallenge := Challenge{}
	header = strings.TrimSpace(header)

	for token := range tokenizeHeader(header) {
		if token.Type == TokenToken {
			if !currentChallenge.IsEmpty() {
				ret = append(ret, currentChallenge)
				currentChallenge = Challenge{}
			}
			currentChallenge.Scheme = token.Token
		}

		if token.Type == TokenAuthParam {
			key, val, _ := strings.Cut(token.Token, "=")
			unquoted, err := strconv.Unquote(val)
			if err == nil {
				val = unquoted
			}
			currentChallenge.setParam(key, val)
		}

		if token.Type == TokenToken68 {
			currentChallenge.addPositionalParam(token.Token)
		}
	}
	ret = append(ret, currentChallenge)
	return ret
}

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
