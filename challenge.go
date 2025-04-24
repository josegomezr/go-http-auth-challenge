package http_auth

import (
	"fmt"
)

// Represents an HTTP Challenge as per RFC 7235 § 2.1
type Challenge struct {
	Scheme string
	Params Params
}

// Challenge & Authorization are effectively the same type
type Authorization = Challenge

// Representation of Authorization Parameters
type Params = map[string]string

// The value for the Token of this particular Authorization.
//
// Using a delimiter for the name is a nice trick to avoid accidental parameter
// overwrites when parsing headers. It's impossible for an authentication
// parameter to have a delimiter in the key as per grammar: <token, see
// [RFC7230], Section 3.2.6>
const TokenParameterName = ":TOKEN68:"

// Initialize a new Challenge
func NewChallenge() Challenge {
	c := Challenge{}
	c.Params = make(map[string]string)
	return c
}

// Get an authentication parameter by name
func (c *Challenge) GetParam(key string) (string, bool) {
	v, ok := c.Params[key]
	return v, ok
}

// Get the default authentication parameter (token)
func (c *Challenge) GetTokenParam() (string, bool) {
	return c.GetParam(TokenParameterName)
}

func (c *Challenge) setParam(key, value string) error {
	if _, ok := c.Params[key]; ok {
		return fmt.Errorf("duplicated authorization parameter %q", key)
	}
	c.Params[key] = value
	return nil
}

func (c *Challenge) setTokenParam(value string) error {
	if err := c.setParam(TokenParameterName, value); err != nil {
		return fmt.Errorf("duplicated authorization value")
	}
	return nil
}

// Checks if a Challenge is empty (Either name is empty or has no params)
func (c *Challenge) IsEmpty() bool {
	return c.Scheme == ""
}

// Shortcut for [Challenge.GetParam]("realm")
func (c *Challenge) Realm() (string, bool) {
	return c.GetParam("realm")
}
