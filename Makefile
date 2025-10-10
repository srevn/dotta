# Dotta - Dotfile Manager Makefile
# C11, libgit2 1.5+

# Compiler and flags
CC := clang
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -Wno-missing-field-initializers -D_DEFAULT_SOURCE
DEBUG_FLAGS := -g -O0 -fsanitize=address,undefined -DDEBUG

# Vendor libraries (must be defined before INCLUDES)
VENDOR_DIR := vendor
CJSON_SRC := $(VENDOR_DIR)/cjson/cJSON.c
TOML_SRC := $(VENDOR_DIR)/toml/tomlc17.c
VENDOR_INCLUDES := -I$(VENDOR_DIR)/cjson -I$(VENDOR_DIR)/toml

# Include paths
INCLUDES := -Iinclude -Isrc $(VENDOR_INCLUDES)

# Dependencies
LIBGIT2_CFLAGS := $(shell pkg-config --cflags libgit2)
LIBGIT2_LIBS := $(shell pkg-config --libs libgit2)

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
CORE_SRC := $(wildcard $(SRC_DIR)/core/*.c)
CMDS_SRC := $(wildcard $(SRC_DIR)/cmds/*.c)
UTILS_SRC := $(wildcard $(SRC_DIR)/utils/*.c)

# Vendor objects
CJSON_OBJ := $(BUILD_DIR)/vendor/cJSON.o
TOML_OBJ := $(BUILD_DIR)/vendor/tomlc17.o

# All source files (excluding main.c for library)
LIB_SRC := $(BASE_SRC) $(INFRA_SRC) $(CORE_SRC) $(CMDS_SRC) $(UTILS_SRC)
LIB_OBJ := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC)) $(CJSON_OBJ) $(TOML_OBJ)

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

$(BUILD_DIR)/base $(BUILD_DIR)/infra $(BUILD_DIR)/core $(BUILD_DIR)/cmds $(BUILD_DIR)/utils $(BUILD_DIR)/vendor:
	@mkdir -p $@

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)/base $(BUILD_DIR)/infra $(BUILD_DIR)/core $(BUILD_DIR)/cmds $(BUILD_DIR)/utils
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) -c $< -o $@

# Compile vendor files
$(BUILD_DIR)/vendor/cJSON.o: $(CJSON_SRC) | $(BUILD_DIR)/vendor
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(VENDOR_INCLUDES) -c $< -o $@

$(BUILD_DIR)/vendor/tomlc17.o: $(TOML_SRC) | $(BUILD_DIR)/vendor
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(VENDOR_INCLUDES) -c $< -o $@

# Link main executable
$(TARGET): $(LIB_OBJ) $(MAIN_OBJ) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(CFLAGS) $^ $(LIBGIT2_LIBS) -o $@

# Debug build
.PHONY: debug
debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic $(DEBUG_FLAGS)
debug: clean $(TARGET)

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
	@install -m 644 $(ETC_DIR)/README.md $(DATADIR)/README.md
	@echo "  Installed: $(DATADIR)/config.toml.sample"
	@echo "  Installed: $(DATADIR)/README.md"
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
	@echo "Installation complete!"
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
	@echo "For more information, see: $(DATADIR)/README.md"

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
	@echo "  debug        - Build with debug symbols"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install binary, configs, and hooks to $(PREFIX)"
	@echo "  uninstall    - Remove installed files from $(PREFIX)"
	@echo "  format       - Format code with clang-format"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  help         - Show this help message"
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
