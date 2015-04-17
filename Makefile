.PHONY: deps fmt test

IMPORT_BASE := github.com/jabley
IMPORT_PATH := $(IMPORT_BASE)/spdy

all: deps _vendor fmt test

deps:
	-go get golang.org/x/tools/cmd/cover

fmt:
	goimports -w *.go

test:
	gom test -v -cover -covermode=atomic --test.coverprofile=spdy.coverprofile \
		. \
	# rewrite the generated .coverprofile files so that you can run the command
	# gom tool cover -html=spdy.coverprofile and other lovely stuff
	find . -name '*.coverprofile' -type f -exec sed -i '' 's|_'$(CURDIR)'|\.|' {} \;

_vendor: Gomfile _vendor/src/$(IMPORT_PATH)
	gom -test install
	touch _vendor

_vendor/src/$(IMPORT_PATH):
	rm -f _vendor/src/$(IMPORT_PATH)
	mkdir -p _vendor/src/$(IMPORT_BASE)
	ln -s $(CURDIR) _vendor/src/$(IMPORT_PATH)
