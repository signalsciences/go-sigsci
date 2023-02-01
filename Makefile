lint:
	go vet
	test -z $(gofmt -s -l .)
test:
	go test -v
