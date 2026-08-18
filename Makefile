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

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -flto $(FEATURE_MACROS)
DEBUG_FLAGS := -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -DDEBUG

# Version information (captured at build time)
GIT_COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell git diff-index --quiet HEAD -- 2>/dev/null || echo "-dirty")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_ARCH := $(shell uname -m)
CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -n1)

# Build type is part of the version banner and varies per target
BUILD_TYPE ?= release

# Vendor libraries
LIB_DIR := lib
CJSON_SRC := $(LIB_DIR)/cjson/cJSON.c
TOML_SRC := $(LIB_DIR)/tomlc17/tomlc17.c
MONOCYPHER_SRC := $(LIB_DIR)/monocypher/monocypher.c
LIB_INCLUDES := -I$(LIB_DIR)/cjson -I$(LIB_DIR)/tomlc17 -I$(LIB_DIR)/monocypher

# Include paths
INCLUDES := -Iinclude -Isrc $(LIB_INCLUDES)

# Version build flags (recursive expansion so target-specific BUILD_TYPE wins)
VERSION_FLAGS = -DDOTTA_BUILD_COMMIT="\"$(GIT_COMMIT)$(GIT_DIRTY)\"" \
                -DDOTTA_BUILD_BRANCH="\"$(GIT_BRANCH)\"" \
                -DDOTTA_BUILD_PLATFORM="\"$(BUILD_OS)/$(BUILD_ARCH)\"" \
                -DDOTTA_BUILD_TYPE="\"$(BUILD_TYPE)\"" \
                -DDOTTA_BUILD_CC="\"$(CC_VERSION)\""

# Dependencies
PKG_CONFIG ?= pkg-config
HAVE_PKG_CONFIG := $(shell command -v $(PKG_CONFIG) 2>/dev/null)

# Version floors
LIBGIT2_MIN := 1.5
SQLITE3_MIN := 3.40

LIBGIT2_VERSION := $(shell $(PKG_CONFIG) --modversion libgit2 2>/dev/null)
LIBGIT2_OK := $(shell $(PKG_CONFIG) --atleast-version=$(LIBGIT2_MIN) libgit2 2>/dev/null && echo 1)
LIBGIT2_CFLAGS := $(shell $(PKG_CONFIG) --cflags libgit2 2>/dev/null)
LIBGIT2_LIBS := $(shell $(PKG_CONFIG) --libs libgit2 2>/dev/null)
LIBGIT2_LIBDIR := $(shell $(PKG_CONFIG) --variable=libdir libgit2 2>/dev/null)
LIBGIT2_STATIC_LIB := $(LIBGIT2_LIBDIR)/libgit2.a
LIBGIT2_STATIC_DEPS := $(shell $(PKG_CONFIG) --libs --static libgit2 2>/dev/null | sed 's/-lgit2//')

SQLITE3_VERSION := $(shell $(PKG_CONFIG) --modversion sqlite3 2>/dev/null)
SQLITE3_OK := $(shell $(PKG_CONFIG) --atleast-version=$(SQLITE3_MIN) sqlite3 2>/dev/null && echo 1)
SQLITE3_CFLAGS := $(shell $(PKG_CONFIG) --cflags sqlite3 2>/dev/null)
SQLITE3_LIBS := $(shell $(PKG_CONFIG) --libs sqlite3 2>/dev/null)

# Package-manager hint
ifeq ($(BUILD_OS),darwin)
define INSTALL_HINT
  brew install pkg-config libgit2 sqlite
endef
else ifeq ($(BUILD_OS),freebsd)
define INSTALL_HINT
  pkg install pkgconf libgit2 sqlite3
endef
else
define INSTALL_HINT
  Debian:    sudo apt install pkg-config libgit2-dev libsqlite3-dev
  Fedora:    sudo dnf install pkgconf-pkg-config libgit2-devel sqlite-devel
  Arch:      sudo pacman -S pkgconf libgit2 sqlite
endef
endif
export INSTALL_HINT

# Goals that need no compiler and no libraries
BUILDLESS_GOALS := clean help check-deps format format-check uninstall uninstall-completions

# Fail at the point of misconfiguration
ifneq ($(filter-out $(BUILDLESS_GOALS),$(or $(MAKECMDGOALS),all)),)
ifeq ($(HAVE_PKG_CONFIG),)
$(error pkg-config not found — install it, then run 'make check-deps')
endif
ifeq ($(LIBGIT2_VERSION),)
$(error libgit2 not found by pkg-config — run 'make check-deps')
endif
ifeq ($(LIBGIT2_OK),)
$(error libgit2 $(LIBGIT2_MIN)+ required, found $(LIBGIT2_VERSION) — run 'make check-deps')
endif
ifeq ($(SQLITE3_VERSION),)
$(error sqlite3 not found by pkg-config — run 'make check-deps')
endif
ifeq ($(SQLITE3_OK),)
$(error sqlite3 $(SQLITE3_MIN)+ required, found $(SQLITE3_VERSION) — run 'make check-deps')
endif
endif

# Check if static library exists
ifneq ($(wildcard $(LIBGIT2_STATIC_LIB)),)
    LIBGIT2_STATIC_LIBS := $(LIBGIT2_STATIC_LIB) $(LIBGIT2_STATIC_DEPS)
    HAS_STATIC_LIBGIT2 := 1
else
    HAS_STATIC_LIBGIT2 := 0
endif

# Uncrustify config
UNCRUSTIFY_CFG := .uncrustify.cfg

# Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
ETC_DIR := etc

# Installation directories
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share/dotta

# Fish completion directory
ifeq ($(BUILD_OS),linux)
    FISHDIR ?= /usr/share/fish/vendor_completions.d
else
    FISHDIR ?= $(PREFIX)/share/fish/vendor_completions.d
endif

# Source files by layer
BASE_SRC := $(wildcard $(SRC_DIR)/base/*.c)
BASE_OBJ := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(BASE_SRC))
SYS_SRC := $(wildcard $(SRC_DIR)/sys/*.c)
INFRA_SRC := $(wildcard $(SRC_DIR)/infra/*.c)
CRYPTO_SRC := $(wildcard $(SRC_DIR)/crypto/*.c)
CORE_SRC := $(wildcard $(SRC_DIR)/core/*.c)
CMDS_SRC := $(wildcard $(SRC_DIR)/cmds/*.c)
UTILS_SRC := $(wildcard $(SRC_DIR)/utils/*.c)

# Library objects
CJSON_OBJ := $(BUILD_DIR)/lib/cJSON.o
TOML_OBJ := $(BUILD_DIR)/lib/tomlc17.o
MONOCYPHER_OBJ := $(BUILD_DIR)/lib/monocypher.o

# All source files (excluding main.c for library)
LIB_SRC := $(BASE_SRC) $(SYS_SRC) $(INFRA_SRC) $(CRYPTO_SRC) $(CORE_SRC) $(CMDS_SRC) $(UTILS_SRC)
LIB_OBJ := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC)) \
           $(CJSON_OBJ) $(TOML_OBJ) $(MONOCYPHER_OBJ)

# Main executable
MAIN_SRC := $(SRC_DIR)/main.c
MAIN_OBJ := $(BUILD_DIR)/main.o
TARGET := $(BIN_DIR)/dotta

# Default target
.PHONY: all
all: $(TARGET)

# Build subdirectories
BUILD_LAYER_DIRS := $(addprefix $(BUILD_DIR)/,base sys infra crypto core cmds utils)
BUILD_SUBDIRS := $(BUILD_LAYER_DIRS) $(BUILD_DIR)/lib $(BUILD_DIR)/completions

# Create directories
$(BUILD_DIR) $(BIN_DIR) $(BUILD_SUBDIRS):
	@mkdir -p $@

# Build configuration sentinel: invalidates every .o when CFLAGS changes.
BUILD_CONFIG := $(BUILD_DIR)/.build-config

.PHONY: FORCE
FORCE:

$(BUILD_CONFIG): FORCE | $(BUILD_DIR)
	@NEW='$(CFLAGS)'; \
	 OLD=$$(cat $@ 2>/dev/null || true); \
	 if [ "$$NEW" != "$$OLD" ]; then \
	   [ -f $@ ] && echo "Build flags changed — rebuilding all objects"; \
	   printf '%s\n' "$$NEW" > $@; \
	 fi

# Header dependencies
DEPFLAGS = -MMD -MP

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(BUILD_CONFIG) | $(BUILD_LAYER_DIRS)
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) $(VERSION_FLAGS) -c $< -o $@

# Compile vendor files
$(BUILD_DIR)/lib/cJSON.o: $(CJSON_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) -c $< -o $@

$(BUILD_DIR)/lib/tomlc17.o: $(TOML_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) -c $< -o $@

$(BUILD_DIR)/lib/monocypher.o: $(MONOCYPHER_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) -c $< -o $@

# Link main executable
$(TARGET): $(LIB_OBJ) $(MAIN_OBJ) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(CFLAGS) $^ $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -o $@

# Debug build
.PHONY: debug
debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror $(DEBUG_FLAGS) $(FEATURE_MACROS)
debug: BUILD_TYPE := debug
debug: $(TARGET)

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

# Tests
TESTS_DIR := tests
TESTS_BIN_DIR := $(TESTS_DIR)/bin
TESTS_SRC := $(wildcard $(TESTS_DIR)/test-*.c)
TESTS_BIN := $(patsubst $(TESTS_DIR)/%.c,$(TESTS_BIN_DIR)/%,$(TESTS_SRC))

$(TESTS_BIN_DIR):
	@mkdir -p $@

$(TESTS_BIN_DIR)/%: $(TESTS_DIR)/%.c $(BASE_OBJ) | $(TESTS_BIN_DIR)
	@echo "CC TEST $<"
	@$(CC) $(CFLAGS) $(INCLUDES) $< $(BASE_OBJ) -o $@

.PHONY: test
test: $(TESTS_BIN)
	@$(TESTS_DIR)/run.sh --unit $(SUITE)

.PHONY: test-cli
test-cli: $(BIN_DIR)/dotta
	@$(TESTS_DIR)/run.sh --cli $(SUITE)

.PHONY: test-all
test-all: $(TESTS_BIN) $(BIN_DIR)/dotta
	@$(TESTS_DIR)/run.sh $(SUITE)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR) $(TESTS_BIN_DIR)

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
	@for f in $(ETC_DIR)/hooks/*.sample; do \
		install -m 755 "$$f" "$(DATADIR)/hooks/$$(basename "$$f")"; \
	done
	@install -m 644 $(ETC_DIR)/hooks/README.md $(DATADIR)/hooks/README.md
	@echo "  Installed: $(DATADIR)/hooks/*.sample"
	@echo "  Installed: $(DATADIR)/hooks/README.md"
	@echo ""

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling dotta..."
	@rm -f $(BINDIR)/dotta
	@echo "  Removed: $(BINDIR)/dotta"
	@rm -rf $(DATADIR)
	@echo "  Removed: $(DATADIR)"
	@rm -f $(FISHDIR)/dotta.fish \
	       $(FISHDIR)/dotta-completions.fish
	@echo "  Removed: $(FISHDIR)/dotta*.fish"
	@echo ""
	@echo "Note: User configurations in ~/.config/dotta were not removed"
	@echo "To remove user configs: rm -rf ~/.config/dotta"

# Fish completion paths
COMPLETIONS_ENTRY := $(ETC_DIR)/completions/dotta.fish
COMPLETIONS_GEN := $(BUILD_DIR)/completions/dotta-completions.fish

# Generate the fish schema from the current binary
$(COMPLETIONS_GEN): $(TARGET) | $(BUILD_DIR)/completions
	@echo "Generating shell completions..."
	@echo ""
	@$(TARGET) __complete spec fish > $@.tmp
	@mv $@.tmp $@

# Convenience alias for the generated schema
.PHONY: completions
completions: $(COMPLETIONS_GEN)

# Install shell completions
.PHONY: install-completions
install-completions: $(COMPLETIONS_GEN)
	@echo "Installing shell completions..."
	@if [ -d "$(FISHDIR)" ] || [ ! -e "$(FISHDIR)" ]; then \
		install -d "$(FISHDIR)" && \
		install -m 644 $(COMPLETIONS_ENTRY) "$(FISHDIR)/dotta.fish" && \
		install -m 644 $(COMPLETIONS_GEN)   "$(FISHDIR)/dotta-completions.fish" && \
		echo "  Installed: $(FISHDIR)/dotta.fish" && \
		echo "  Installed: $(FISHDIR)/dotta-completions.fish"; \
	else \
		echo "  Skipped fish completions ($(FISHDIR) exists but is not a directory)"; \
	fi

# Uninstall shell completions
.PHONY: uninstall-completions
uninstall-completions:
	@echo "Removing shell completions..."
	@rm -f "$(FISHDIR)/dotta.fish" \
	       "$(FISHDIR)/dotta-completions.fish"
	@echo "  Removed: $(FISHDIR)/dotta.fish"
	@echo "  Removed: $(FISHDIR)/dotta-completions.fish"

# Install all (binary + completions)
.PHONY: install-all
install-all: install
	@$(MAKE) --no-print-directory install-completions

# Shared find expression for C sources and headers
FORMAT_FIND := src include \( -name "*.c" -o -name "*.h" \)

# Format code (requires uncrustify)
.PHONY: format
format:
	@echo "Formatting code..."
	@find $(FORMAT_FIND) | xargs -I{} uncrustify -c $(UNCRUSTIFY_CFG) -l C --no-backup {}

# Check formatting without modifying files
.PHONY: format-check
format-check:
	@find $(FORMAT_FIND) | xargs -I{} uncrustify -c $(UNCRUSTIFY_CFG) -l C --check {} 2>&1 | grep FAIL; \
	if [ $$? -eq 0 ]; then echo "Formatting issues found. Run 'make format' to fix."; exit 1; \
	else echo "All files formatted correctly."; fi

# Static analysis with clang-tidy (requires compile_commands.json)
TIDY ?= clang-tidy
RUN_TIDY ?= run-clang-tidy
TIDY_JOBS ?= $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
TIDY_FILTER ?= ^.*/src/.*\.c$$
TIDY_FILES ?= $(LIB_SRC) $(MAIN_SRC)

.PHONY: tidy
tidy:
	@if [ ! -f compile_commands.json ]; then \
		echo "Error: compile_commands.json not found. Generate it with 'make compile-commands'."; \
		exit 1; \
	fi
	@echo "Running clang-tidy in parallel ($(TIDY_JOBS) jobs)..."
	@$(RUN_TIDY) -p . -quiet -j $(TIDY_JOBS) '$(TIDY_FILTER)'

.PHONY: tidy-fix
tidy-fix:
	@if [ ! -f compile_commands.json ]; then \
		echo "Error: compile_commands.json not found. Generate it with 'make compile-commands'."; \
		exit 1; \
	fi
	@echo "Running clang-tidy with --fix in parallel ($(TIDY_JOBS) jobs)..."
	@$(RUN_TIDY) -p . -quiet -j $(TIDY_JOBS) -fix '$(TIDY_FILTER)'

# Scan a single file (serial, useful for targeted checks)
.PHONY: tidy-file
tidy-file:
	@if [ -z "$(FILE)" ]; then echo "Usage: make tidy-file FILE=src/path/to/file.c"; exit 1; fi
	@$(TIDY) -p . --quiet $(FILE)

# Regenerate compile_commands.json via bear
.PHONY: compile-commands
compile-commands:
	@command -v bear >/dev/null 2>&1 || \
		{ echo "Error: 'bear' not installed. Install via: brew install bear"; exit 1; }
	@$(MAKE) clean
	@bear -- $(MAKE) -j$$(sysctl -n hw.ncpu 2>/dev/null || nproc)

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@fail=0; \
	 if [ -n "$(HAVE_PKG_CONFIG)" ]; then \
	   printf '  %-12s %s\n' "pkg-config" "$(HAVE_PKG_CONFIG)"; \
	 else \
	   printf '  %-12s %s\n' "pkg-config" "NOT FOUND (required to locate libgit2 and sqlite3)"; \
	   fail=1; \
	 fi; \
	 if command -v $(CC) >/dev/null 2>&1; then \
	   printf '  %-12s %s\n' "$(CC)" "$$($(CC) --version | head -n1)"; \
	 else \
	   printf '  %-12s %s\n' "$(CC)" "NOT FOUND"; \
	   fail=1; \
	 fi; \
	 if [ -z "$(LIBGIT2_VERSION)" ]; then \
	   printf '  %-12s %s\n' "libgit2" "NOT FOUND (need >= $(LIBGIT2_MIN))"; \
	   fail=1; \
	 elif [ -z "$(LIBGIT2_OK)" ]; then \
	   printf '  %-12s %s\n' "libgit2" "$(LIBGIT2_VERSION) — TOO OLD (need >= $(LIBGIT2_MIN))"; \
	   fail=1; \
	 else \
	   printf '  %-12s %s\n' "libgit2" "$(LIBGIT2_VERSION) (>= $(LIBGIT2_MIN))"; \
	 fi; \
	 if [ -z "$(SQLITE3_VERSION)" ]; then \
	   printf '  %-12s %s\n' "sqlite3" "NOT FOUND (need >= $(SQLITE3_MIN))"; \
	   fail=1; \
	 elif [ -z "$(SQLITE3_OK)" ]; then \
	   printf '  %-12s %s\n' "sqlite3" "$(SQLITE3_VERSION) — TOO OLD (need >= $(SQLITE3_MIN))"; \
	   fail=1; \
	 else \
	   printf '  %-12s %s\n' "sqlite3" "$(SQLITE3_VERSION) (>= $(SQLITE3_MIN))"; \
	 fi; \
	 echo ""; \
	 if [ $$fail -ne 0 ]; then \
	   echo "Missing or outdated dependencies. Install with:"; \
	   printf '%s\n' "$$INSTALL_HINT"; \
	   exit 1; \
	 fi; \
	 echo "All dependencies satisfied."

# Help
.PHONY: help
help:
	@echo "dotta Makefile targets:"
	@echo "  all                   - Build main executable (default)"
	@echo "  debug                 - Build with debug symbols"
	@echo "  static                - Build with libgit2 statically linked (portable)"
	@echo "  test                  - Build and run unit tests"
	@echo "  test-cli              - Run CLI suites (SUITE=\"ghosts export\" to filter)"
	@echo "  test-all              - Run unit tests and CLI suites"
	@echo "  clean                 - Remove build artifacts"
	@echo "  completions           - Regenerate dotta-completions.fish from current binary"
	@echo "  install               - Install binary, configs, and hooks to $(PREFIX)"
	@echo "  install-completions   - Install fish shell completions"
	@echo "  install-all           - Install binary, configs, hooks, and completions"
	@echo "  uninstall             - Remove installed files from $(PREFIX)"
	@echo "  uninstall-completions - Remove shell completions only"
	@echo "  format                - Format code with uncrustify"
	@echo "  format-check          - Check formatting without modifying files"
	@echo "  tidy                  - Run clang-tidy static analysis (parallel)"
	@echo "  tidy-fix              - Run clang-tidy and apply safe fixes (parallel)"
	@echo "  tidy-file FILE=...    - Run clang-tidy on a single file"
	@echo "  compile-commands      - Regenerate compile_commands.json via bear"
	@echo "  check-deps            - Check for required dependencies"
	@echo "  help                  - Show this help message"
	@echo ""
	@echo "Installation paths:"
	@echo "  Binary:       $(BINDIR)/dotta"
	@echo "  Configs:      $(DATADIR)/"
	@echo "  Hooks:        $(DATADIR)/hooks/"
	@echo "  Completions:  $(FISHDIR)/dotta.fish"
	@echo ""
	@echo "Override PREFIX with: make install PREFIX=/custom/path"

# Dependency tracking
-include $(LIB_OBJ:.o=.d)
-include $(MAIN_OBJ:.o=.d)
