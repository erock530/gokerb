SHELL := /bin/bash


godep:
	@go get -u -v github.com/golang/dep/cmd/dep
	@dep ensure -v -vendor-only

krb5: ## Build krb5 library
	@if [ ! -d "../../krb5/krb5" ] ;\
	then \
		mkdir ../../krb5; \
		echo "krb5 does not exist, cloning"; \
		git clone https://github.com/krb5/krb5.git ../../krb5/krb5; \
		cd ../../krb5/krb5/src; \
		autoreconf; \
		./configure; \
		make -j 8 all; \
	fi

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
