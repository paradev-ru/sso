.PHONY: run all linux

run:
	@go run cmd/sso/main.go \
		-log-level 'debug' \
		-upstream-url 'http://127.0.0.1:8081' \
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

deploy: linux
	@echo "--> Uploading..."
	scp -P 3389 sso.local leo@paradev.ru:/etc/default/sso
	scp -P 3389 contrib/init/sysvinit-debian/sso leo@paradev.ru:/etc/init.d/sso
	scp -P 3389 bin/sso leo@paradev.ru:/opt/sso/sso_new
	@echo "--> Restarting..."
	ssh -p 3389 leo@paradev.ru service sso stop
	ssh -p 3389 leo@paradev.ru rm /opt/sso/sso
	ssh -p 3389 leo@paradev.ru mv /opt/sso/sso_new /opt/sso/sso
	ssh -p 3389 leo@paradev.ru service sso start
	@echo "--> Getting last logs..."
	@ssh -p 3389 leo@paradev.ru tail -n 25 /var/log/sso.log
