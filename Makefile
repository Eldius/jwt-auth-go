
clean:
	-go clean -testcache
	-rm coverage.*

test: clean
	go test ./... -cover -timeout 4s

lint:
	revive -formatter friendly ./...

vulnerabilities:
	snyk test

coverage-html:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

coverage-console:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
