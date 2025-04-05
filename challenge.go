package http_auth

import (
	"fmt"
)

// Represents an HTTP Challenge as per RFC 7235 § 2.1
type Challenge struct {
	Scheme string
	Params []AuthParam
}

// Challenge & Authorization are effectively the same type
type Authorization = Challenge

// Get the first value of the challenge. Useful to get Tokens out of Authorization Basic or Bearer
func (c *Challenge) GetFirstValue(key string) (string, bool) {
	if len(c.Params) == 0 {
		return "", false
	}
	return c.Params[0].Value, true
}

// Get an auth-param by name. Non-named auth-params (like tokens) are saved in
// order of discovery (meaning "0" is the first Token after the auth scheme)
func (c *Challenge) GetParam(key string) (string, bool) {
	for _, param := range c.Params {
		if param.Key == key {
			return param.Value, true
		}
	}
	return "", false
}

func (c *Challenge) setParam(key, value string) {
	c.Params = append(c.Params, AuthParam{
		Key:   key,
		Value: value,
	})
}

func (c *Challenge) addPositionalParam(value string) {
	key := fmt.Sprintf("%d", len(c.Params))
	c.setParam(key, value)
}

// Checks if a Challenge is empty (Either name is empty or has no params)
func (c *Challenge) IsEmpty() bool {
	return c.Scheme == "" || len(c.Params) == 0
}

// Shortcut for [Challenge.GetParam]("realm")
func (c *Challenge) Realm() (string, bool) {
	return c.GetParam("realm")
}
