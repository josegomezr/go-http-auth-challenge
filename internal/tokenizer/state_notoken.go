package tokenizer

type stateNOTOKEN string

func (t stateNOTOKEN) Consume(c rune, yield func(Token) bool) State {
	return stateToken(c)
}

func (t stateNOTOKEN) AsToken() Token {
	return Token{NOTOKEN, string(t)}
}
