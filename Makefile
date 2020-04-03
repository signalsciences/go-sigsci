lint:
	go vet
	test -z $(gofmt -s -l .)
test:
	go test -v
publish: test
	git tag -fa v0.3.0
	git push origin --tags

