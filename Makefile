.PHONY: build clean install test run

BINARY=ads-process-monitor
VERSION=0.1.0

build:
	go build -ldflags "-X github.com/afterdarksystems/ads-process-monitor/cmd.Version=$(VERSION)" -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	cp $(BINARY) /usr/local/bin/

test:
	go test -v ./...

run: build
	./$(BINARY)

deps:
	go mod tidy

# Quick commands for testing
list: build
	./$(BINARY) list

tree: build
	./$(BINARY) tree

watch: build
	./$(BINARY) watch

serve: build
	./$(BINARY) serve

json: build
	./$(BINARY) list --output-json
