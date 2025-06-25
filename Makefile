# Compiler and flags
CXX = g++
CXXFLAGS = -g -O0 -fdiagnostics-color=always
LDFLAGS =


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
BUILD_DIR = build
LIB_DIR = .
EXAMPLES_DIR = examples
PREFIX ?= /usr/local
INSTALLINCLUDEDIR = $(PREFIX)/include/cssl
INSTALLLIBDIR = $(PREFIX)/lib
TEST_DIRS = tests/aes tests/ecdsa_siggen tests/ecdsa_sigverif tests/hash

# Source files and object files (excluding main.cpp)
SRCS = $(filter-out $(SRC_DIR)/main.cpp,$(wildcard $(SRC_DIR)/*.cpp))
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# Output objects
SHARED_LIB = $(LIB_DIR)/libcssl.so
STATIC_LIB = $(LIB_DIR)/libcssl.a

all: $(SHARED_LIB) $(STATIC_LIB) examples

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(SHARED_LIB): $(OBJS)
	$(CXX) -shared -o $@ $(OBJS) $(LDFLAGS)

$(STATIC_LIB): $(OBJS)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -fPIC -c $< -o $@

examples:
	$(MAKE) -C $(EXAMPLES_DIR)

clean:
	rm -rf $(BUILD_DIR) $(SHARED_LIB) $(STATIC_LIB)
	$(MAKE) -C $(EXAMPLES_DIR) clean
	$(MAKE) -C tests/aes clean
	$(MAKE) -C tests/ecdsa_siggen clean
	$(MAKE) -C tests/ecdsa_sigverif clean
	$(MAKE) -C tests/hash clean
install: all
	install -d $(INSTALLINCLUDEDIR)
	cp -r ./inc/* $(INSTALLINCLUDEDIR)/
	install -d $(INSTALLLIBDIR)
	install -m 755 $(SHARED_LIB) $(INSTALLLIBDIR)
	install -m 644 $(STATIC_LIB) $(INSTALLLIBDIR)
uninstall:
	rm -f $(INSTALLLIBDIR)/libcssl.so
	rm -f $(INSTALLLIBDIR)/libcssl.a
	rm -rf $(INSTALLINCLUDEDIR)
test: all
	@for dir in $(TEST_DIRS); do \
		$(MAKE) -C $$dir run; \
	done

PHONY: all examples clean install uninstall test
