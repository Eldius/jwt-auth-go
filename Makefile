
test:
	go clean -testcache
	go test ./... -cover -timeout 1s

lint:
	revive -formatter friendly ./...

coverage-html:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

coverage-console:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
