# Dotta - Dotfile Manager Makefile
# C11, libgit2 1.5+

# Compiler and flags
CC := clang

# Version information
BUILD_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')

# Platform-specific feature test macros
ifeq ($(BUILD_OS),linux)
    # Linux: POSIX + default BSD/SVID extensions
    FEATURE_MACROS := -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE
else ifeq ($(BUILD_OS),darwin)
    # macOS: POSIX + Darwin extensions
    FEATURE_MACROS := -D_XOPEN_SOURCE=700 -D_DARWIN_C_SOURCE
else ifeq ($(BUILD_OS),freebsd)
    # FreeBSD: POSIX + BSD extensions
    FEATURE_MACROS := -D_XOPEN_SOURCE=700 -D__BSD_VISIBLE
else
    # Fallback for other POSIX systems
    FEATURE_MACROS := -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE
endif

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -Wno-missing-field-initializers $(FEATURE_MACROS)
DEBUG_FLAGS := -g -O0 -fsanitize=address,undefined -DDEBUG

# Version information (captured at build time)
GIT_COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
GIT_COMMIT_FULL := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell git diff-index --quiet HEAD -- 2>/dev/null || echo "-dirty")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_ARCH := $(shell uname -m)
CC_VERSION := $(shell $(CC) --version | head -n1)

# Vendor libraries (must be defined before INCLUDES)
LIB_DIR := lib
CJSON_SRC := $(LIB_DIR)/cjson/cJSON.c
TOML_SRC := $(LIB_DIR)/toml/tomlc17.c
HYDROGEN_SRC := $(LIB_DIR)/hydrogen/hydrogen.c
LIB_INCLUDES := -I$(LIB_DIR)/cjson -I$(LIB_DIR)/toml -I$(LIB_DIR)/hydrogen

# Include paths
INCLUDES := -Iinclude -Isrc $(LIB_INCLUDES)

# Version build flags
VERSION_FLAGS := -DDOTTA_BUILD_COMMIT="\"$(GIT_COMMIT)$(GIT_DIRTY)\"" \
                 -DDOTTA_BUILD_COMMIT_FULL="\"$(GIT_COMMIT_FULL)\"" \
                 -DDOTTA_BUILD_BRANCH="\"$(GIT_BRANCH)\"" \
                 -DDOTTA_BUILD_OS="\"$(BUILD_OS)\"" \
                 -DDOTTA_BUILD_ARCH="\"$(BUILD_ARCH)\"" \
                 -DDOTTA_BUILD_CC="\"$(CC_VERSION)\""

# Dependencies
LIBGIT2_CFLAGS := $(shell pkg-config --cflags libgit2)
LIBGIT2_LIBS := $(shell pkg-config --libs libgit2)
LIBGIT2_LIBDIR := $(shell pkg-config --variable=libdir libgit2)
LIBGIT2_STATIC_LIB := $(LIBGIT2_LIBDIR)/libgit2.a
LIBGIT2_STATIC_DEPS := $(shell pkg-config --libs --static libgit2 | sed 's/-lgit2//')

SQLITE3_CFLAGS := $(shell pkg-config --cflags sqlite3)
SQLITE3_LIBS := $(shell pkg-config --libs sqlite3)

# Check if static library exists
ifneq ($(wildcard $(LIBGIT2_STATIC_LIB)),)
    LIBGIT2_STATIC_LIBS := $(LIBGIT2_STATIC_LIB) $(LIBGIT2_STATIC_DEPS)
    HAS_STATIC_LIBGIT2 := 1
else
    HAS_STATIC_LIBGIT2 := 0
endif

# Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
ETC_DIR := etc

# Installation directories
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share/dotta

# Source files by layer
BASE_SRC := $(wildcard $(SRC_DIR)/base/*.c)
INFRA_SRC := $(wildcard $(SRC_DIR)/infra/*.c)
CRYPTO_SRC := $(wildcard $(SRC_DIR)/crypto/*.c)
CORE_SRC := $(wildcard $(SRC_DIR)/core/*.c)
CMDS_SRC := $(wildcard $(SRC_DIR)/cmds/*.c)
UTILS_SRC := $(wildcard $(SRC_DIR)/utils/*.c)

# Library objects
CJSON_OBJ := $(BUILD_DIR)/lib/cJSON.o
TOML_OBJ := $(BUILD_DIR)/lib/tomlc17.o
HYDROGEN_OBJ := $(BUILD_DIR)/lib/hydrogen.o

# All source files (excluding main.c for library)
LIB_SRC := $(BASE_SRC) $(INFRA_SRC) $(CRYPTO_SRC) $(CORE_SRC) $(CMDS_SRC) $(UTILS_SRC)
LIB_OBJ := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC)) $(CJSON_OBJ) $(TOML_OBJ) $(HYDROGEN_OBJ)

# Main executable
MAIN_SRC := $(SRC_DIR)/main.c
MAIN_OBJ := $(BUILD_DIR)/main.o
TARGET := $(BIN_DIR)/dotta

# Default target
.PHONY: all
all: $(TARGET)

# Create directories
$(BUILD_DIR) $(BIN_DIR):
	@mkdir -p $@

$(BUILD_DIR)/base $(BUILD_DIR)/infra $(BUILD_DIR)/crypto $(BUILD_DIR)/core $(BUILD_DIR)/cmds $(BUILD_DIR)/utils $(BUILD_DIR)/lib:
	@mkdir -p $@

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)/base $(BUILD_DIR)/infra $(BUILD_DIR)/crypto $(BUILD_DIR)/core $(BUILD_DIR)/cmds $(BUILD_DIR)/utils
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) $(VERSION_FLAGS) -c $< -o $@

# Compile vendor files
$(BUILD_DIR)/lib/cJSON.o: $(CJSON_SRC) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(LIB_INCLUDES) -c $< -o $@

$(BUILD_DIR)/lib/tomlc17.o: $(TOML_SRC) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(LIB_INCLUDES) -c $< -o $@

$(BUILD_DIR)/lib/hydrogen.o: $(HYDROGEN_SRC) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(LIB_INCLUDES) -c $< -o $@

# Link main executable
$(TARGET): $(LIB_OBJ) $(MAIN_OBJ) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(CFLAGS) $^ $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -o $@

# Debug build
.PHONY: debug
debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Valgrind memory testing
.PHONY: valgrind memcheck
VALGRIND_FLAGS ?= --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose
VALGRIND_CMD ?= init

valgrind: memcheck
memcheck:
	@if ! command -v valgrind >/dev/null 2>&1; then \
		echo "Error: valgrind not found"; \
		echo ""; \
		echo "Install valgrind:"; \
		echo "  macOS:  brew install valgrind"; \
		echo "  Linux:  apt-get install valgrind  (Debian/Ubuntu)"; \
		echo "          dnf install valgrind      (Fedora/RHEL)"; \
		echo ""; \
		exit 1; \
	fi
	@echo "Building debug binary for valgrind..."
	@$(MAKE) debug CC=gcc CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -g -O0 $(FEATURE_MACROS)"
	@echo ""
	@echo "Running: valgrind $(VALGRIND_FLAGS) $(TARGET) $(VALGRIND_CMD)"
	@echo ""
	@valgrind $(VALGRIND_FLAGS) $(TARGET) $(VALGRIND_CMD)

# Static build (with libgit2 statically linked for portability)
.PHONY: static
static:
	@if [ "$(HAS_STATIC_LIBGIT2)" = "0" ]; then \
		echo "Error: libgit2 static library not found at $(LIBGIT2_STATIC_LIB)"; \
		echo ""; \
		echo "To build a static binary, you need libgit2 compiled with static libraries."; \
		echo ""; \
		echo "On macOS with Homebrew:"; \
		echo "  Static libraries are usually included in the libgit2 package"; \
		echo ""; \
		echo "On FreeBSD:"; \
		echo "  pkg install libgit2 only provides shared libraries"; \
		echo "  You may need to build libgit2 from source with -DBUILD_SHARED_LIBS=OFF"; \
		echo ""; \
		echo "On Debian/Ubuntu:"; \
		echo "  sudo apt install libgit2-dev"; \
		echo ""; \
		exit 1; \
	fi
	@$(MAKE) clean
	@$(MAKE) LIBGIT2_LIBS="$(LIBGIT2_STATIC_LIBS)" $(TARGET)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)

# Install
.PHONY: install
install: $(TARGET)
	@echo "Installing binary..."
	@install -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/dotta
	@echo "  Installed: $(BINDIR)/dotta"
	@echo ""
	@echo "Installing configuration samples..."
	@install -d $(DATADIR)
	@install -m 644 $(ETC_DIR)/config.toml.sample $(DATADIR)/config.toml.sample
	@echo "  Installed: $(DATADIR)/config.toml.sample"
	@echo ""
	@echo "Installing hook samples..."
	@install -d $(DATADIR)/hooks
	@install -m 755 $(ETC_DIR)/hooks/pre-apply.sample $(DATADIR)/hooks/pre-apply.sample
	@install -m 755 $(ETC_DIR)/hooks/post-apply.sample $(DATADIR)/hooks/post-apply.sample
	@install -m 755 $(ETC_DIR)/hooks/pre-add.sample $(DATADIR)/hooks/pre-add.sample
	@install -m 755 $(ETC_DIR)/hooks/post-add.sample $(DATADIR)/hooks/post-add.sample
	@install -m 644 $(ETC_DIR)/hooks/README.md $(DATADIR)/hooks/README.md
	@echo "  Installed: $(DATADIR)/hooks/*.sample"
	@echo "  Installed: $(DATADIR)/hooks/README.md"
	@echo ""
	@echo "Quick start:"
	@echo "  1. Copy sample config:"
	@echo "     mkdir -p ~/.config/dotta"
	@echo "     cp $(DATADIR)/config.toml.sample ~/.config/dotta/config.toml"
	@echo ""
	@echo "  2. Initialize repository:"
	@echo "     dotta init"
	@echo ""
	@echo "  3. Add your first file:"
	@echo "     dotta add --profile global ~/.bashrc"
	@echo ""

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling dotta..."
	@rm -f $(BINDIR)/dotta
	@echo "  Removed: $(BINDIR)/dotta"
	@rm -rf $(DATADIR)
	@echo "  Removed: $(DATADIR)"
	@echo ""
	@echo "Note: User configurations in ~/.config/dotta were not removed"
	@echo "To remove user configs: rm -rf ~/.config/dotta"

# Format code (requires clang-format)
.PHONY: format
format:
	@echo "Formatting code..."
	@find src include -name "*.c" -o -name "*.h" | xargs clang-format -i

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libgit2 && echo "libgit2 found" || (echo "libgit2 not found" && exit 1)
	@which $(CC) > /dev/null && echo "$(CC) found" || (echo "$(CC) not found" && exit 1)

# Help
.PHONY: help
help:
	@echo "Dotta Makefile targets:"
	@echo "  all          - Build main executable (default)"
	@echo "  debug        - Build with debug symbols and sanitizers"
	@echo "  valgrind     - Run valgrind memory checks (alias: memcheck)"
	@echo "  static       - Build with libgit2 statically linked (portable)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install binary, configs, and hooks to $(PREFIX)"
	@echo "  uninstall    - Remove installed files from $(PREFIX)"
	@echo "  format       - Format code with clang-format"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Valgrind usage:"
	@echo "  make valgrind                                 - Test 'dotta init'"
	@echo "  make valgrind VALGRIND_CMD='status'           - Test 'dotta status'"
	@echo "  make valgrind VALGRIND_CMD='add ~/.bashrc'    - Test 'dotta add ~/.bashrc'"
	@echo "  make valgrind VALGRIND_FLAGS='--leak-check=full --log-file=valgrind.log'"
	@echo ""
	@echo "Installation paths:"
	@echo "  Binary:      $(BINDIR)/dotta"
	@echo "  Configs:     $(DATADIR)/"
	@echo "  Hooks:       $(DATADIR)/hooks/"
	@echo ""
	@echo "Override PREFIX with: make install PREFIX=/custom/path"

# Dependency tracking
-include $(LIB_OBJ:.o=.d)
-include $(MAIN_OBJ:.o=.d)

# Generate dependencies
$(BUILD_DIR)/%.d: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) -MM -MT $(BUILD_DIR)/$*.o $< > $@
