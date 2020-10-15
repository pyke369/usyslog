#!/bin/sh

# build targets
usyslog: *.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; go build -trimpath -o usyslog
	@-strip usyslog 2>/dev/null || true
	@-upx -9 usyslog 2>/dev/null || true
clean:
distclean:
	@rm -f usyslog
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../usyslog_*

# run targets
run: usyslog
	@./usyslog /tmp/usyslog tcp://localhost
