
clean:
	-go clean -testcache
	-rm coverage.*

test: clean
	go test ./... -cover -timeout 2s
	@echo "---"
	@echo

lint:
	revive -formatter friendly ./...
	@echo "---"
	@echo

vulnerabilities:
	snyk test
	@echo "---"
	@echo

coverage-html:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

coverage-console:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

all: lint vulnerabilities test
	@echo "Finished all code validations"
