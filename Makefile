.PHONY: test test-with-coverage

test:
	go test -v ./...

test-with-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

setup-localstack:
	docker compose up -d localstack

teardown-localstack:
	docker compose down

fuzz-with-localstack: setup-localstack
	go test -fuzz=FuzzSignMessage -fuzztime=5m
	go test -fuzz=FuzzPublicKeyFormat -fuzztime=5m
	make teardown-localstack

test-with-localstack: setup-localstack
	go test -v ./...
	make teardown-localstack