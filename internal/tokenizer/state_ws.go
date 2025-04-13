package tokenizer

type stateWS string

func (t stateWS) AsToken() Token {
	return Token{TokenWS, string(t)}
}

func (t stateWS) Consume(c rune, yield func(Token) bool) State {
	if c == ' ' {
		return t
	}

	if c == ',' {
		return stateComma(c)
	}

	return stateToken68(c)
}
