deposit-backend: $(shell find . -name '*.go')
	go build -o deposit-backend . 

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run
	npx --yes @redocly/cli lint backend_oapi.json

.PHONY: test
test:
	go test ./...

.PHONY: test-verbose
test-verbose:
	go test -v ./...

cover.out: $(shell find . -name '*.go')
	go test -coverpkg=./... -coverprofile=cover.out ./...

.PHONY: cover
cover: cover.out
	go tool cover -html=cover.out

.PHONY: clean
clean:
	rm -f cover.out