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

# Build type: release | debug. `make debug` = `make BUILD_TYPE=debug`. Each
# type owns an object tree (build/<type>/) and a binary (bin/dotta,
# bin/dotta-debug), so the two stand side by side: switching rebuilds nothing,
# and a sanitizer run of the suites never displaces the release binary.
BUILD_TYPE ?= $(if $(filter debug,$(MAKECMDGOALS)),debug,release)
ifeq ($(filter $(BUILD_TYPE),release debug),)
$(error BUILD_TYPE must be 'release' or 'debug' (got '$(BUILD_TYPE)'))
endif

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror $(FEATURE_MACROS)
ifeq ($(BUILD_TYPE),debug)
CFLAGS += -g -O0 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
else
CFLAGS += -O2 -flto
endif

# The archiver behind the unit binaries' library. A release object is LLVM
# bitcode (-flto) and an archive's symbol table is read off its members: the
# compiler's own llvm-ar reads bitcode, a system ar need not (Apple's does,
# GNU ar only through a plugin). Ask the compiler, and fall back to the system
# ar when it names none — the answer is a bare name rather than a path.
AR := $(shell $(CC) -print-prog-name=llvm-ar 2>/dev/null)
ifeq ($(filter /%,$(AR)),)
AR := ar
endif

# Version information (captured at build time)
GIT_COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell git diff-index --quiet HEAD -- 2>/dev/null || echo "-dirty")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_ARCH := $(shell uname -m)
CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -n1)

# Vendor libraries
LIB_DIR := lib
CJSON_SRC := $(LIB_DIR)/cjson/cJSON.c
TOML_SRC := $(LIB_DIR)/tomlc17/tomlc17.c
MONOCYPHER_SRC := $(LIB_DIR)/monocypher/monocypher.c
LIB_INCLUDES := -I$(LIB_DIR)/cjson -I$(LIB_DIR)/tomlc17 -I$(LIB_DIR)/monocypher

# Include paths
INCLUDES := -Iinclude -Isrc $(LIB_INCLUDES)

# Version build flags — the banner's compile-time constants
VERSION_FLAGS := -DDOTTA_BUILD_COMMIT="\"$(GIT_COMMIT)$(GIT_DIRTY)\"" \
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
BUILDLESS_GOALS := clean help check-deps format format-check reflow reflow-check uninstall uninstall-completions

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

# Uncrustify config
UNCRUSTIFY_CFG := .uncrustify.cfg

# Directories — the object tree is the build type's
SRC_DIR := src
BUILD_ROOT := build
BUILD_DIR := $(BUILD_ROOT)/$(BUILD_TYPE)
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

# Main executable — the type's own name, so both can stand in bin/
MAIN_SRC := $(SRC_DIR)/main.c
MAIN_OBJ := $(BUILD_DIR)/main.o
ifeq ($(BUILD_TYPE),debug)
TARGET := $(BIN_DIR)/dotta-debug
else
TARGET := $(BIN_DIR)/dotta
endif

# Default target
.PHONY: all
all: $(TARGET)

# Build subdirectories
BUILD_LAYER_DIRS := $(addprefix $(BUILD_DIR)/,base sys infra crypto core cmds utils)
BUILD_SUBDIRS := $(BUILD_LAYER_DIRS) $(BUILD_DIR)/lib $(BUILD_DIR)/completions

# Create directories
$(BUILD_DIR) $(BIN_DIR) $(BUILD_SUBDIRS):
	@mkdir -p $@

# Build configuration sentinel: how this tree's objects were produced. A tree
# is one build type's for life, so the stamp is the flags alone.
BUILD_CONFIG := $(BUILD_DIR)/.build-config
BUILD_STAMP := $(CC) $(CFLAGS) $(INCLUDES) \
               $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) $(LIBGIT2_LIBS) $(SQLITE3_LIBS)

.PHONY: FORCE
FORCE:

$(BUILD_CONFIG): FORCE | $(BUILD_DIR)
	@NEW='$(BUILD_STAMP)'; \
	 OLD=$$(cat $@ 2>/dev/null || true); \
	 if [ "$$NEW" = "$$OLD" ]; then exit 0; fi; \
	 [ -z "$$OLD" ] || echo "Build config changed — rebuilding all objects"; \
	 printf '%s\n' "$$NEW" > $@

# Version sentinel: the banner's constants change with every commit and with
# the first edit after one.
VERSION_CONFIG := $(BUILD_DIR)/.version-config

$(VERSION_CONFIG): FORCE | $(BUILD_DIR)
	@NEW='$(VERSION_FLAGS)'; \
	 OLD=$$(cat $@ 2>/dev/null || true); \
	 [ "$$NEW" = "$$OLD" ] || printf '%s\n' "$$NEW" > $@

# Header dependencies
DEPFLAGS = -MMD -MP

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(BUILD_CONFIG) | $(BUILD_LAYER_DIRS)
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) -c $< -o $@

# The banner renderer: the one translation unit that reads VERSION_FLAGS, so
# the one that carries them and follows the version sentinel.
$(BUILD_DIR)/utils/version.o: $(SRC_DIR)/utils/version.c $(BUILD_CONFIG) $(VERSION_CONFIG) | $(BUILD_LAYER_DIRS)
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
	@echo "LD $@ ($(BUILD_TYPE))"
	@$(CC) $(CFLAGS) $^ $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -o $@

# Debug build
.PHONY: debug
debug: all

# The library — every object but main's — archived for the unit binaries,
# which link it and take the members they reference: a base suite pulls a
# handful of objects, a core suite the layers beneath it, and neither pays
# the whole program's link. Rebuilt from scratch: `ar r` replaces and adds,
# it never drops the member of a source that is gone.
LIBDOTTA := $(BUILD_DIR)/libdotta.a

$(LIBDOTTA): $(LIB_OBJ)
	@echo "AR $@"
	@rm -f $@
	@$(AR) rcs $@ $^

# Tests — the unit binaries live in the build type's tree beside the objects
# they were linked from; under BUILD_TYPE=debug they are sanitizer binaries,
# the runtime coming in through the same flags on the link.
TESTS_DIR := tests
TESTS_BIN_DIR := $(BUILD_DIR)/tests
TESTS_SRC := $(wildcard $(TESTS_DIR)/test-*.c)
TESTS_BIN := $(patsubst $(TESTS_DIR)/%.c,$(TESTS_BIN_DIR)/%,$(TESTS_SRC))

$(TESTS_BIN_DIR):
	@mkdir -p $@

$(TESTS_BIN_DIR)/%: $(TESTS_DIR)/%.c $(LIBDOTTA) | $(TESTS_BIN_DIR)
	@echo "CC TEST $<"
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INCLUDES) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) \
	    $< $(LIBDOTTA) $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -o $@

# Suites are independent; run this many at a time (JOBS=1 keeps start order)
JOBS ?= 4

# The runner drives this build type's binary and unit binaries; run by hand
# it defaults to the release ones (tests/run.sh).
RUN_SUITES := DOTTA=$(CURDIR)/$(TARGET) DOTTA_TEST_UNIT_DIR=$(CURDIR)/$(TESTS_BIN_DIR) \
              $(TESTS_DIR)/run.sh -j$(JOBS)

.PHONY: test
test: $(TESTS_BIN)
	@$(RUN_SUITES) --unit $(SUITE)

.PHONY: test-cli
test-cli: $(TARGET)
	@$(RUN_SUITES) --cli $(SUITE)

.PHONY: test-all
test-all: $(TESTS_BIN) $(TARGET)
	@$(RUN_SUITES) $(SUITE)

# Clean build artifacts — both build types
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_ROOT) $(BIN_DIR)

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
	@rm -f $(FISHDIR)/dotta.fish
	@echo "  Removed: $(FISHDIR)/dotta.fish"
	@echo ""
	@echo "Note: User configurations in ~/.config/dotta were not removed"
	@echo "To remove user configs: rm -rf ~/.config/dotta"

# Fish completions: the whole script is generated from the binary's command registry
COMPLETIONS_GEN := $(BUILD_DIR)/completions/dotta.fish

$(COMPLETIONS_GEN): $(TARGET) | $(BUILD_DIR)/completions
	@echo "Generating shell completions..."
	@echo ""
	@$(TARGET) completion fish > $@.tmp
	@mv $@.tmp $@

# Convenience alias for the generated script
.PHONY: completions
completions: $(COMPLETIONS_GEN)

# Install shell completions
.PHONY: install-completions
install-completions: $(COMPLETIONS_GEN)
	@echo "Installing shell completions..."
	@if [ -d "$(FISHDIR)" ] || [ ! -e "$(FISHDIR)" ]; then \
		install -d "$(FISHDIR)" && \
		install -m 644 $(COMPLETIONS_GEN) "$(FISHDIR)/dotta.fish" && \
		echo "  Installed: $(FISHDIR)/dotta.fish"; \
	else \
		echo "  Skipped fish completions ($(FISHDIR) exists but is not a directory)"; \
	fi

# Uninstall shell completions
.PHONY: uninstall-completions
uninstall-completions:
	@echo "Removing shell completions..."
	@rm -f "$(FISHDIR)/dotta.fish"
	@echo "  Removed: $(FISHDIR)/dotta.fish"

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
	@find $(FORMAT_FIND) -print0 | xargs -0 uncrustify -c $(UNCRUSTIFY_CFG) -l C --no-backup -q

# Check formatting without modifying files
.PHONY: format-check
format-check:
	@find $(FORMAT_FIND) -print0 | xargs -0 uncrustify -c $(UNCRUSTIFY_CFG) -l C --check -q \
	  || { echo "Formatting issues found. Run 'make format' to fix."; exit 1; }
	@echo "All files formatted correctly."

# Reflow block comments (requires python3). Runs after uncrustify, never before:
# the fill column is measured from the comment's own indent, so the reindent has
# to land first or the column it just produced is gone.
REFLOW := scripts/reflow_comments.py
REFLOW_WIDTH ?= 80
REFLOW_SLACK ?= 4
# Scope is what git says changed. Override with REFLOW_FILES="src/a.c include/b.h".
REFLOW_FILES ?= $(shell git diff --name-only HEAD -- 'src/*.c' 'src/*.h' 'include/*.h')

.PHONY: reflow
reflow:
	@command -v python3 >/dev/null 2>&1 || \
	  { echo "Error: python3 not installed."; exit 1; }
	@if [ -z "$(REFLOW_FILES)" ]; then \
	  echo "No modified .c/.h files to reflow."; \
	else \
	  echo "Reflowing comments..."; \
	  python3 $(REFLOW) --width $(REFLOW_WIDTH) --slack $(REFLOW_SLACK) --apply $(REFLOW_FILES); \
	fi

# Show what reflow would change without writing; non-zero if anything would
.PHONY: reflow-check
reflow-check:
	@if [ -n "$(REFLOW_FILES)" ]; then \
	  python3 $(REFLOW) --width $(REFLOW_WIDTH) --slack $(REFLOW_SLACK) $(REFLOW_FILES) \
	    || { echo "Comment reflow pending. Run 'make reflow' to fix."; exit 1; }; \
	fi
	@echo "All comments reflowed correctly."

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
	@echo "  all                   - Build main executable (default): bin/dotta"
	@echo "  debug                 - Build with debug symbols and sanitizers: bin/dotta-debug"
	@echo "  test                  - Build and run unit tests"
	@echo "  test-cli              - Run CLI suites (SUITE=\"ghosts export\" to filter, JOBS=1 for start order)"
	@echo "  test-all              - Run unit tests and CLI suites"
	@echo "  clean                 - Remove build artifacts (both build types)"
	@echo "  completions           - Generate the fish completion script from the binary"
	@echo "  install               - Install binary, configs, and hooks to $(PREFIX)"
	@echo "  install-completions   - Install fish shell completions"
	@echo "  install-all           - Install binary, configs, hooks, and completions"
	@echo "  uninstall             - Remove installed files from $(PREFIX)"
	@echo "  uninstall-completions - Remove shell completions only"
	@echo "  format                - Format code with uncrustify"
	@echo "  format-check          - Check formatting without modifying files"
	@echo "  reflow                - Reflow comments in git-modified .c/.h files"
	@echo "  reflow-check          - Show pending comment reflow without writing"
	@echo "  tidy                  - Run clang-tidy static analysis (parallel)"
	@echo "  tidy-fix              - Run clang-tidy and apply safe fixes (parallel)"
	@echo "  tidy-file FILE=...    - Run clang-tidy on a single file"
	@echo "  compile-commands      - Regenerate compile_commands.json via bear"
	@echo "  check-deps            - Check for required dependencies"
	@echo "  help                  - Show this help message"
	@echo ""
	@echo "Build type: 'debug' as a goal or BUILD_TYPE=debug sets the whole invocation,"
	@echo "so 'make debug test-all' runs the suites under ASan/UBSan. Each type has its"
	@echo "own tree (build/<type>/) and binary, so the two coexist."
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
-include $(TESTS_BIN:=.d)
