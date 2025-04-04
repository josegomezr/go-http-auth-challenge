package http_auth

import (
	"fmt"
)

type Challenge struct {
	Scheme       string
	Params       []AuthParam
}
// Challenge & Authorization are effectively the same type
type Authorization = Challenge

func (c *Challenge) GetFirstValue(key string) (string, bool) {
	if len(c.Params) == 0 {
		return "", false
	}
	return c.Params[0].Key, true
}

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

func (c *Challenge) IsEmpty() bool {
	return c.Scheme == "" || len(c.Params) == 0
}

func (c *Challenge) Realm() (string, bool) {
	return c.GetParam("realm")
}
