# Copyright IBM Corp All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#		 http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -------------------------------------------------------------
# This makefile defines the following targets
#
#   - all (default) - builds all targets and runs all tests
#   - license - check all go files for license headers
#   - cop - builds the cop executable
#   - unit-tests - Performs checks first and runs the go-test based unit tests
#   - checks - runs all check conditions (license, format, imports, lint and vet)

PROJECT_NAME   = hyperledger/fabric
BASE_VERSION   = 0.7.0
IS_RELEASE     = false

ifneq ($(IS_RELEASE),true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION=$(BASE_VERSION)-$(EXTRA_VERSION)
else
PROJECT_VERSION=$(BASE_VERSION)
endif

# Check that all dependencies are installed
EXECUTABLES = go docker git curl
K := $(foreach exec,$(EXECUTABLES),\
	$(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH: Check dependencies")))

#PROJECT_FILES = $(shell git ls-files)
ARCH=$(shell uname -m)
BASEIMAGE_RELEASE=$(shell cat ./.baseimage-release)
PKGNAME = github.com/hyperledger/fabric-cop
pkgmap.cop := $(PKGNAME)/cli

#IMAGES = cop testenv runtime
IMAGES = cop runtime

include docker-env.mk

all: docker unit-tests

docker: $(patsubst %,build/image/%/$(DUMMY), $(IMAGES))

checks: license vet lint format imports

license: .FORCE
	@scripts/check_license

format: .FORCE
	@scripts/check_format

imports: .FORCE
	@scripts/check_imports

lint: .FORCE
	@scripts/check_lint

vet: .FORCE
	@scripts/check_vet

bin/cop:
	@echo "Building cop in bin directory ..."
	@mkdir -p bin && cd cli && go build -o ../bin/cop
	@echo "Built bin/cop"

# We (re)build a package within a docker context but persist the $GOPATH/pkg
# directory so that subsequent builds are faster
build/docker/bin/cop:
	$(eval TARGET = ${patsubst build/docker/bin/%,%,${@}})
	@echo "Building $@"
	@mkdir -p build/docker/bin build/docker/$(TARGET)/pkg
	@$(DRUN) \
		-v $(abspath build/docker/bin):/opt/gopath/bin \
		-v $(abspath build/docker/$(TARGET)/pkg):/opt/gopath/pkg \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		go install -ldflags "$(DOCKER_GO_LDFLAGS)" $(pkgmap.$(@F))
	mv build/docker/bin/cli build/docker/bin/cop
	@touch $@

build/docker/busybox:
	@$(DRUN) \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		make -f busybox/Makefile install BINDIR=$(@D)

build/image/cop/$(DUMMY): build/image/runtime/$(DUMMY)

# payload definitions'
build/image/cop/payload:	build/docker/bin/cop
#build/image/testenv/payload:    build/gotools.tar.bz2
build/image/runtime/payload:	build/docker/busybox

build/image/%/payload:
	mkdir -p $@
	cp $^ $@

build/image/%/$(DUMMY): Makefile build/image/%/payload
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	@echo "Building docker $(TARGET)-image"
	@cat images/$(TARGET)/Dockerfile.in \
		| sed -e 's/_BASE_TAG_/$(BASE_DOCKER_TAG)/g' \
		| sed -e 's/_TAG_/$(DOCKER_TAG)/g' \
		> $(@D)/Dockerfile
	$(DBUILD) -t $(PROJECT_NAME)-$(TARGET) $(@D)
	docker tag $(PROJECT_NAME)-$(TARGET) $(PROJECT_NAME)-$(TARGET):$(DOCKER_TAG)
	@touch $@

unit-tests: checks bin/cop
	@scripts/run_tests

container-tests: ldap-tests

ldap-tests:
	@scripts/run_ldap_tests

%-docker-clean:
	$(eval TARGET = ${patsubst %-docker-clean,%,${@}})
	-docker images -q $(PROJECT_NAME)-$(TARGET) | xargs -I '{}' docker rmi -f '{}'
	-@rm -rf build/image/$(TARGET) ||:

docker-clean: $(patsubst %,%-docker-clean, $(IMAGES))

.PHONY: clean
clean: docker-clean
	-@rm -rf build bin ||:

.FORCE:
