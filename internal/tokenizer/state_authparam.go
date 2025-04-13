package tokenizer

type stateAuthParam struct {
	value      string
	quotecount int
	isescaping bool
}

func (t stateAuthParam) AsToken() Token {
	return Token{TokenAuthParam, t.value}
}

func (t stateAuthParam) Consume(c rune, yield func(Token) bool) State {
	if t.quotecount > 2 {
		yield(stateNOTOKEN(t.value).AsToken())
		return stateNOTOKEN(t.value)
	}

	if c == 0 {
		yield(t.AsToken())
		return t
	}

	if t.isescaping {
		t.isescaping = false
		t.value += string(c)

		return t
	}

	if c == '\\' {
		t.isescaping = true
		t.value += string(c)

		return t
	}

	if t.quotecount%2 == 1 && c == ' ' {

		t.value += string(c)
		return t
	}

	if c == '"' {
		t.quotecount += 1
		t.value += string(c)

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

	t.value += string(c)
	return t
}
