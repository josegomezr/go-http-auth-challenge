package http_auth

import (
	"errors"
	"strconv"
	"fmt"
	"strings"
)

func parseHeader(header string, strict bool) ([]Challenge) {
	ret := []Challenge{}
	currentChallenge := Challenge{}
	currentParams := AuthParam{}

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

			currentParams.Key = key
			currentParams.Value = val
			currentChallenge.Params = append(currentChallenge.Params, currentParams)
			currentParams = AuthParam{}
		}

		if token.Type == TokenToken68 {
			currentParams.Key = fmt.Sprintf("%d", len(currentChallenge.Params))
			currentParams.Value = token.Token
			currentChallenge.Params = append(currentChallenge.Params, currentParams)
			currentParams = AuthParam{}
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

func ParseAuthorizations(header string, strict bool) ([]Challenge, error) {
	challenges := parseHeader(header, strict)
	challengeCount := len(challenges)
	if challengeCount == 0 {
		return nil, errors.New("no challenges could be parsed")
	}

	return challenges, nil
}
