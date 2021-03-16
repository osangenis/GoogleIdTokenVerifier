#!/bin/bash
# vim: ai:ts=8:sw=8:noet
# Runs Go unit test suite 

go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

# Display coverage
# go tool cover -func=.test_coverage.txt | tail -n1 | awk '{print "Total test coverage: " $3}'