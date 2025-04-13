package tokenizer

type stateToken string

func (t stateToken) AsToken() Token {
	return Token{TokenToken, string(t)}
}

func (t stateToken) Consume(c rune, yield func(Token) bool) State {
	if c == 0 {
		yield(t.AsToken())
		return t
	}

	if c == ' ' {
		yield(t.AsToken())
		return stateWS(c)
	}

	if c == ',' {
		yield(t.AsToken())
		return stateComma(c)
	}

	if c == '=' {
		return stateToken68(string(t) + string(c))
	}

	t += stateToken(c)
	return t
}
