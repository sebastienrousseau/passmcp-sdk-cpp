# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

CMAKE ?= cmake
CTEST ?= ctest
BUILD_DIR ?= build

LOCAL_ECOSYSTEM := $(abspath ../../Go/passmcp/ecosystem.json)
ifneq ($(wildcard $(LOCAL_ECOSYSTEM)),)
PASSMCP_ECOSYSTEM_URL ?= file://$(LOCAL_ECOSYSTEM)
endif

.PHONY: all check configure build lint test reuse family lockstep example clean

all: check

check: lint test reuse family lockstep example

configure:
	$(CMAKE) -B $(BUILD_DIR)

build: configure
	$(CMAKE) --build $(BUILD_DIR)

lint: build

test: build
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure

reuse:
	reuse lint

family:
	PASSMCP_ECOSYSTEM_URL="$(PASSMCP_ECOSYSTEM_URL)" ./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example: build
	./$(BUILD_DIR)/quickstart

clean:
	rm -rf $(BUILD_DIR)
