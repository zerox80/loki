CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Iinclude $(shell $(PKG_CONFIG) --cflags openssl)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl)
BUILD ?= build

PROTOCOL_SOURCES := src/protocol/frame.c src/protocol/hello.c src/protocol/ipv4.c src/protocol/mtu.c
SOURCES := src/app/main.c src/app/options.c \
           src/runtime/clock.c src/runtime/signals.c src/platform/linux/tun.c \
           src/transport/udp.c src/crypto/context.c src/crypto/cookie.c \
           src/crypto/handshake.c src/crypto/io.c src/session/session.c $(PROTOCOL_SOURCES)
OBJECTS := $(SOURCES:%.c=$(BUILD)/%.o)
TEST_OBJECTS := $(BUILD)/tests/unit/protocol_test.o $(PROTOCOL_SOURCES:%.c=$(BUILD)/%.o)
DEPS := $(OBJECTS:.o=.d) $(BUILD)/tests/unit/protocol_test.d

.PHONY: all clean test integration
all: $(BUILD)/loki

$(BUILD)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/loki: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/protocol_test: $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(BUILD)/protocol_test
	$(BUILD)/protocol_test

integration: all
	python3 tests/integration/network.py --binary $(abspath $(BUILD)/loki) --work-dir $(abspath $(BUILD)/test-work)

clean:
	rm -rf -- $(BUILD)

-include $(DEPS)
