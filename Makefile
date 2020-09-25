lint:
	go vet
	golint
	test -z $(gofmt -s -l .)
test:
	go test -v
