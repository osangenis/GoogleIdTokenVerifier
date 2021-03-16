#!/bin/bash
# vim: ai:ts=8:sw=8:noet
# Runs golang-ci-lint suite of linters
# configuration is in .golangci.yml

# Check required commands are in place
# Double check you have --> export PATH=$PATH:$(go env GOPATH)/bin
command -v golangci-lint >/dev/null 2>&1 || { echo 'please install golangci-lint or use an image that has it'; exit 1; }
golangci-lint run


