.PHONY: test

test:
	# small sublime-text-3 hack to have clickable errors on the log panel
	go test -fullpath ./... | sed -E "s#^ +##g"

