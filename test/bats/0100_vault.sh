#!/usr/bin/env bats

@test "vault is running" {
  [ "$(ps -efl | grep -v grep | grep vault)"] != "" ]
}

@test "can login to vault" {
  vault login root
}
