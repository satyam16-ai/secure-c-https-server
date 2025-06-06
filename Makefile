# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Wno-error -Wno-format-truncation -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -I/usr/include/openssl
DEBUG_CFLAGS = -g -O0 -DDEBUG
RELEASE_CFLAGS = -O2 -DNDEBUG

# Libraries
LDFLAGS = -lssl -lcrypto -lpthread

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
INC_DIR = include

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/https_server

# Unit tests
TEST_SRC = tests/test_config.c src/config.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_BIN = bin/tests

CFLAGS_TEST = $(CFLAGS) -Iinclude -Itests
LDLIBS_TEST = -lcheck -lm -lsubunit

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Debug build
debug: CFLAGS += $(DEBUG_CFLAGS)
debug: clean all

# Release build
release: CFLAGS += $(RELEASE_CFLAGS)
release: clean all

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Install (requires root)
install: release
	install -m 755 $(TARGET) /usr/local/bin/
	install -d /etc/https_server
	install -m 644 certs/cert.pem /etc/https_server/
	install -m 600 certs/key.pem /etc/https_server/

# Uninstall
uninstall:
	rm -f /usr/local/bin/https_server
	rm -rf /etc/https_server

# Run tests
test: $(TEST_BIN)
	./$(TEST_BIN)

# Generate SSL certificates (for development)
certs:
	openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build the server (default)"
	@echo "  debug      - Build with debug flags"
	@echo "  release    - Build with optimization flags"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install the server (requires root)"
	@echo "  uninstall  - Uninstall the server"
	@echo "  test       - Run tests"
	@echo "  certs      - Generate development SSL certificates"
	@echo "  help       - Show this help message"

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS_TEST) -o $@ $(TEST_SRC) $(LDLIBS_TEST)

.PHONY: all debug release clean install uninstall test certs help directories
