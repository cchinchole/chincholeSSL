# Compiler and flags
DEBUG = 0
OPT_LEVEL = 3
CXX = g++
CXXFLAGS = -std=c++23 -g -O$(OPT_LEVEL) -DDEBUG=$(DEBUG) -fdiagnostics-color=always -I../inc
LDFLAGS = -L../ -l:libcssl.a

# Use pkg-config to get OpenSSL flags
OPENSSL_PKG = libssl3
OPENSSL_CFLAGS := $(shell pkg-config --cflags $(OPENSSL_PKG) 2>/dev/null || pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs $(OPENSSL_PKG) 2>/dev/null || pkg-config --libs openssl 2>/dev/null)

# Allow user overrides via environment variables
OPENSSL_CFLAGS ?= $(OPENSSL_CFLAGS)
OPENSSL_LIBS ?= $(OPENSSL_LIBS)

# Add OpenSSL flags to compiler and linker flags
CXXFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

# Directories
SRC_DIR = .
BIN_DIR = bin

# Source files for test applications
TEST_SRCS = $(wildcard $(SRC_DIR)/*.cpp)
TEST_EXECS = $(patsubst $(SRC_DIR)/%.cpp,$(BIN_DIR)/%,$(TEST_SRCS))

# Default target
all: $(BIN_DIR) $(TEST_EXECS)

# Create bin directory
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build each test application directly
$(BIN_DIR)/%: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Clean up
clean:
	rm -rf $(BIN_DIR)

# Phony targets
.PHONY: all clean
