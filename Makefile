.PHONY: test

test:
	go test -fullpath ./... | sed -E "s#^ +##g"

