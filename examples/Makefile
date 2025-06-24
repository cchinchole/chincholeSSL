# Compiler and flags
CXX = g++
CXXFLAGS = -g -O0 -fdiagnostics-color=always -I../inc
LDFLAGS = -I/usr/include/openssl -I/usr/include/openssl3 -lssl -lcrypto -L../ -lcsll

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
