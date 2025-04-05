package http_auth

// Represents an auth-param as per RFC 7235 § 2.1
type AuthParam struct {
	Key   string
	Value string
}
