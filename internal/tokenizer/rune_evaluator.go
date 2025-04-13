package tokenizer

import (
	"iter"
	"strings"
)

type State interface {
	Consume(c rune, fn func(Token) bool) State
	AsToken() Token
}

// Represents a fully formed token recognized by the parser
// See grammars in RFC 7230 § 3.2.6 & RFC 7235 § 2.1
type Token struct {
	Type  TokenType
	Value string
}

func Tokenize(header string) iter.Seq[Token] {
	var currentState State = stateNOTOKEN("")
	header = strings.TrimSpace(header)
	return func(yield func(Token) bool) {
		for _, c := range header {
			currentState = currentState.Consume(c, yield)
		}
		currentState.Consume(0, yield)
	}
}
