lint:
	go vet
	test -z $(gofmt -s -l .)
