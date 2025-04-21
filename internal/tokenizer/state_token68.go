package tokenizer

import (
	"strings"
	"unicode"
)

type stateToken68 string

func (t stateToken68) AsToken() Token {
	return Token{TokenToken68, string(t)}
}

func isToken68Char(c rune) bool {
	punctuation := "-._~+/"
	return unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune(punctuation, c)
}

func (t stateToken68) Consume(c rune, yield func(Token) bool) State {
	if c == 0 {
		yield(t.AsToken())
		return t
	}

	if c == ',' {
		yield(t.AsToken())
		return stateComma(c)
	}

	if c == '=' {
		t += stateToken68(c)
		return t
	}

	if c == ' ' {
		yield(stateToken(string(t)).AsToken())
		return stateWS(c)
	}

	newval := string(t) + string(c)

	lastChar := t[len(t)-1]
	if lastChar == '=' {
		quotecount := 0
		if c == '"' {
			quotecount = 1
		}
		return stateAuthParam{value: newval, quotecount: quotecount}
	}

	if isToken68Char(c) {
		t += stateToken68(c)
		return t
	}

	return stateNOTOKEN(newval)
}
