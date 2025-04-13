package tokenizer

type stateComma string

func (t stateComma) AsToken() Token {
	return Token{TokenComma, string(t)}
}

func (t stateComma) Consume(c rune, yield func(Token) bool) State {
	if c == ' ' {
		return stateWS(c)
	}

	return stateToken68(c)
}
