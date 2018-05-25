###############################################################################
# Go Builder layer

# from https://github.com/naveego/vault-jose-plugin/blob/master/dockerfile
FROM golang:latest as builder

WORKDIR /go/src/gitlab.com/gbevan/vault-e2e-plugin

# install dep
RUN go get github.com/golang/dep/cmd/dep

#install ginkgo
RUN go get -u github.com/onsi/ginkgo/ginkgo

# add Gopkg.toml and Gopkg.lock
ADD Gopkg.toml Gopkg.toml
ADD Gopkg.lock Gopkg.lock

# install packages
RUN dep ensure -v --vendor-only

ADD . .

#RUN go test -v ./...
RUN ls -la plugin/
RUN pwd
RUN go env

##################
# build the plugin
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/e2e-plugin
#RUN go build -o build/e2e-plugin
RUN shasum -a 256 -p build/e2e-plugin | cut -d ' ' -f 1 > "build/e2e-plugin.sha"

# build the utils
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o build/genrsapair genrsapair/genrsapair.go
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o build/decrypt decrypt/decrypt.go

RUN ls -la build/

###############################################################################
# Vault layer
## build the docker container with vault and the plugin mounted
FROM vault:latest

ENV VAULT_PORT 8200
ENV VAULT_TOKEN ""
ENV VAULT_ADDR "http://0.0.0.0:${VAULT_PORT}"
ENV VAULT_CLUSTER_ADDR ""
ENV VAULT_API_ADDR ""
ENV VAULT_LOCAL_CONFIG '{ "plugin_directory": "/vault/plugins" }'
ENV VAULT_DEV_ROOT_TOKEN_ID "root"
ENV VAULT_LOG_LEVEL "trace"

RUN apk update && apk add curl jq bats

RUN mkdir -p /vault/plugins
RUN mkdir -p /vault/data

EXPOSE ${VAULT_PORT}

WORKDIR /vault/plugins
COPY --from=builder /go/src/gitlab.com/gbevan/vault-e2e-plugin/build /vault/plugins

ADD ./test ./test
RUN chmod a+x ./test/*.sh ./test/bats/*.sh

ENTRYPOINT [ "./test/start_vault.sh" ]

# mount point for a vault config
VOLUME [ "/vault/config" ]

CMD ["server", "-dev"]
