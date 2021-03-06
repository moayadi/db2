GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-db2 cmd/vault-plugin-secrets-db2/main.go
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/example cmd/example/main.go

start:
	vault server -dev -dev-root-token-id=root -log-level=trace -dev-plugin-dir=./vault/plugins -dev-listen-address="0.0.0.0:8200"

enable:
	vault secrets enable -path=db2 vault-plugin-secrets-hashicups

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-mock

commands:
	./commands.sh

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
