.PHONY: run all linux

run:
	@go run cmd/sso/main.go \
		-log-level 'debug' \
		-upstream-url 'http://paradev.ru' \
		-app-url 'http://127.0.0.1:8080' \
		-listen-addr '127.0.0.1:8080' \
		-encryption-key 'eeveidee1ahcuRuyae7no0Eizuechohj' \
		-state-string 'ooyoobu9vuo1haezae7koh3zai3hee1R' \
		-authorized-users 'leominov,jidckii'

all:
	@mkdir -p bin/
	@bash --norc -i ./scripts/build.sh

linux:
	@mkdir -p bin/
	@export GOOS=linux && export GOARCH=amd64 && bash --norc -i ./scripts/build.sh
