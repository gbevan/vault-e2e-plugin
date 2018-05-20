#!/bin/bash -e

docker build --tag vault-e2e .
docker run --rm --name vault-e2e \
  -p 8210:8200 \
  --cap-add IPC_LOCK \
  --volume `pwd`/test/:/vault/plugins/test/ \
  vault-e2e
