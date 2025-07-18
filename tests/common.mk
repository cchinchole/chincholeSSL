# Compiler and flags
DEBUG = 0
OPT_LEVEL = 3
CXX = g++
CXXFLAGS = -std=c++23 -g -O$(OPT_LEVEL) -DDEBUG=$(DEBUG) -fdiagnostics-color=always -I../../inc
LDFLAGS = -L../../ -l:libcssl.a

# OpenSSL flags
OPENSSL_PKG = libssl3
OPENSSL_CFLAGS := $(shell pkg-config --cflags $(OPENSSL_PKG) 2>/dev/null || pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs $(OPENSSL_PKG) 2>/dev/null || pkg-config --libs openssl 2>/dev/null)

CXXFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

SRC_DIR = .
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
EXECS = $(patsubst $(SRC_DIR)/%.cpp,$(BIN_DIR)/%,$(SRCS))

all: $(BIN_DIR) $(EXECS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

run: all
	LD_LIBRARY_PATH=../../ $(BIN_DIR)/*

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean run
