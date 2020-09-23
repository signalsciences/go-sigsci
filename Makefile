lint:
	go vet
	golint
	test -z $(gofmt -s -l .)
test:
	go test -v
<<<<<<< HEAD
publish: test
	git tag -fa v0.3.0
	git push origin --tags

=======
>>>>>>> upstream/master
