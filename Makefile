lint:
	go vet
	./scripts/gofmt.sh
test:
	go test -v
