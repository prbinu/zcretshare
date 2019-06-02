# Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
# Copyrights licensed under the BSD 3-Clause License. See the
# accompanying LICENSE.txt file for terms.

.PHONY: all build test release clean
SHELL := /bin/bash

VERSION := 1.0.0
DATE := $(shell date +"%Y-%m-%d")
ARCH := $(shell go version | awk '{print $$4}' | tr '/' '-')

LDFLAGS=-ldflags "-w -X main.releaseDate=$(DATE) -X main.versionNumber=$(VERSION)"

build:
	go fmt
	go build -o zcretshare $(LDFLAGS) zcretshare.go

test:
	go test

release:
	tar zcvf bin/zcretshare-$(VERSION)-$(ARCH).tgz zcretshare

all: build test release

install:
	tar -C /usr/local/bin -xzf bin/zcretshare-$(VERSION)-$(ARCH).tgz

uninstall:
	rm /usr/local/bin/zcretshare

clean:
	rm ./zcretshare
	rm ./zcretshare_test
