BUILD_DIR ?= ./build/build
SRC_DIRS ?= ../src . ../examples

TEST_SRCS := $(shell find $(SRC_DIRS) -name \*.cpp \! -name mock.cpp \! -name CMakeCXXCompilerId.cpp)
TEST_OBJS := $(TEST_SRCS:%=$(BUILD_DIR)/%.o)
TEST_DEPS := $(TEST_OBJS:.o=.d)

MOCK_SRCS := $(shell find $(SRC_DIRS) -name \*.cpp \! -name SNMP_Embedded.cpp \! -name tests.cpp \! -name CMakeCXXCompilerId.cpp)
MOCK_OBJS := $(MOCK_SRCS:%=$(BUILD_DIR)/%.o)
MOCK_DEPS := $(MOCK_OBJS:.o=.d)

EXAMPLE_SRCS := $(shell find $(SRC_DIRS) \( -name \*.cpp -o -name ESP32_SNMP.ino \) \! -name mock.cpp \! -name tests.cpp \! -name CMakeCXXCompilerId.cpp)
EXAMPLE_OBJS := $(EXAMPLE_SRCS:%=$(BUILD_DIR)/%.o)

.DELETE_ON_ERROR:

CC = c++
CXX = c++

CPPFLAGS ?= -I"../src" -I"../" -MMD -MP -std=c++11 \
	-Wpedantic \
	-Wextra \
	-Wall \
	-Wno-error=sequence-point \
	-Wno-error=write-strings \
	-Werror \
	-DCOMPILING_TESTS	

ifdef DEBUG
	CPPFLAGS += -DDEBUG -g
endif
help:
	@echo "test: Make & Run tests"
	@echo "ci-test: clean first, then make & run tests (for GitHub Actions / CI runners with build-dir caching)"

$(BUILD_DIR)/test: $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/mock: $(MOCK_OBJS)
	$(CC) $(MOCK_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/example: $(EXAMPLE_OBJS)
	$(CC) $(EXAMPLE_OBJS) -o $@ $(LDFLAGS)
# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
	
# inosource
$(BUILD_DIR)/%.ino.o: %.ino
	$(MKDIR_P) $(dir $@)
	cp $< $@.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I"required" -c $@.cpp -o $@
	rm $@.cpp


.PHONY: clean test benchmark example ci-test test-nobuiltinuptime ci-test-nobuiltinuptime test-nozc ci-test-nozc

# v3.3.4: opt-out profile — SNMP_NO_BUILTIN_SYSUPTIME build. Separate BUILD_DIR
# so the two profiles never share stale objects. Verifies (a) clean compile with
# the flag, (b) pool/callback counts exactly one less than the default build,
# (c) sysUpTime behaves as an unregistered OID.
# NOTE on the "$(BUILD_DIR)/../src" object paths: the ../ escapes BUILD_DIR,
# so every non-default profile compiles into the SHARED ./src/ dir. Each
# profile therefore MUST clear ./src first, or it silently reuses the previous
# profile's objects (observed live: notraps linked against stale nozc objects).
test-nobuiltinuptime:
	$(MAKE) BUILD_DIR=./build-nouptime clean
	$(RM) -r ./src
	$(MAKE) BUILD_DIR=./build-nouptime CPPFLAGS="$(CPPFLAGS) -DSNMP_NO_BUILTIN_SYSUPTIME" test

# v3.4.0: classic-path escape-hatch profile — SNMP_ZERO_COPY=0. Separate
# BUILD_DIR. Verifies (a) the owning-container path still compiles with the
# zero-copy fast path compiled out, and (b) its suite stays green, so
# -DSNMP_ZERO_COPY=0 remains a valid field escape hatch.
test-nozc:
	$(MAKE) BUILD_DIR=./build-nozc clean
	$(RM) -r ./src
	$(MAKE) BUILD_DIR=./build-nozc CPPFLAGS="$(CPPFLAGS) -DSNMP_ZERO_COPY=0" test

ci-test-nobuiltinuptime: test-nobuiltinuptime

# v3.4.1: traps/informs compiled out — SNMP_NO_TRAPS=1. Verifies (a) the
# library compiles with the whole trap/inform path removed, (b) the derived
# pool drops the 16-slot trap-tree term (formula case), and (c) the
# remaining suite stays green.
test-notraps:
	$(MAKE) BUILD_DIR=./build-notraps clean
	$(RM) -r ./src
	$(MAKE) BUILD_DIR=./build-notraps CPPFLAGS="$(CPPFLAGS) -DSNMP_NO_TRAPS=1" test

ci-test-notraps: test-notraps

ci-test-nozc: test-nozc

clean:
	$(RM) -r ./build
	$(RM) *.d
	$(RM) *.o


test: $(BUILD_DIR)/test
	$(BUILD_DIR)/test -s

mock: $(BUILD_DIR)/mock
	$(BUILD_DIR)/mock
	
example: $(BUILD_DIR)/example

ci-test: clean test

-include $(MOCK_DEPS) $(TEST_DEPS) 

MKDIR_P ?= mkdir -p
