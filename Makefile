# Compiler and flags
CXX = g++
CXXFLAGS = -g -O0 -fdiagnostics-color=always
LDFLAGS = -I/usr/include/openssl -I/usr/include/openssl3 -I/usr/include/openssl/openssl -I/usr/include/openssl3/openssl -L/lib64/ -lssl -lcrypto

# Directories
SRC_DIR = .
BUILD_DIR = build
LIB_DIR = .
EXAMPLES_DIR = examples

# Source files and object files (excluding main.cpp)
SRCS = $(filter-out $(SRC_DIR)/main.cpp,$(wildcard $(SRC_DIR)/*.cpp))
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))
LIB = $(LIB_DIR)/libcsll.so

# Default target
all: $(LIB) examples

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Build shared library
$(LIB): $(OBJS)
	$(CXX) -shared -o $(LIB) $(OBJS) $(LDFLAGS)

# Compile source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -fPIC -c $< -o $@

# Build examples by invoking the Makefile in examples/
examples:
	$(MAKE) -C $(EXAMPLES_DIR)

# Clean up
clean:
	rm -rf $(BUILD_DIR) $(LIB)
	$(MAKE) -C $(EXAMPLES_DIR) clean

# Phony targets
.PHONY: all examples clean
