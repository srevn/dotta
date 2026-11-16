# Dotta - Dotfile Manager Makefile
# C11, libgit2 1.9+

# Compiler: the user's CC, else clang
ifeq ($(origin CC),default)
CC := clang
endif

# The system make runs on: the feature macros, the paths and hints, and the
# bundled libraries' TLS read it
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

# Build type: release | debug | coverage
BUILD_TYPE ?= $(firstword $(filter debug coverage,$(MAKECMDGOALS:coverage-report=coverage)) release)
ifeq ($(filter $(BUILD_TYPE),release debug coverage),)
$(error BUILD_TYPE must be 'release', 'debug' or 'coverage' (got '$(BUILD_TYPE)'))
endif

# Dependencies: system | bundled
DEPS ?= system
ifeq ($(filter $(DEPS),system bundled),)
$(error DEPS must be 'system' or 'bundled' (got '$(DEPS)'))
endif

# The build's own flags, by build type. The user's CPPFLAGS, CFLAGS and LDFLAGS
# come after them and win: CFLAGS=-Wno-error keeps a warning a warning
BUILD_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Werror $(FEATURE_MACROS)
ifeq ($(BUILD_TYPE),debug)
BUILD_CFLAGS += -g -O0 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
else ifeq ($(BUILD_TYPE),coverage)
BUILD_CFLAGS += -g -O0 -fprofile-instr-generate -fcoverage-mapping
else
BUILD_CFLAGS += -O2 -flto
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

# Version information (captured at build time). git is asked of this directory
# alone, as git's own build asks: a tree inside another repository, an unpacked
# archive among them, names no commit. The commit as `git log --oneline`
# abbreviates it; -dirty where a tracked file's bytes differ (git diff reads a
# file whose stat alone moved, which diff-index calls changed, and refreshes the
# index as git status does); no branch where HEAD is detached. The compiler names
# itself, and the target it compiles for under the user's CFLAGS (-arch among
# them): what the binary is built for, never the machine building it
GIT := GIT_CEILING_DIRECTORIES="$(CURDIR)/.." git
GIT_COMMIT := $(shell $(GIT) rev-parse -q --verify --short HEAD 2>/dev/null)
GIT_DIRTY := $(if $(GIT_COMMIT),$(shell $(GIT) diff --quiet HEAD -- 2>/dev/null || echo -dirty))
GIT_BRANCH := $(shell $(GIT) symbolic-ref -q --short HEAD 2>/dev/null)
CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -n1)
CC_MACHINE := $(shell $(CC) $(CFLAGS) -dumpmachine 2>/dev/null)

# Vendor libraries
LIB_DIR := lib
CJSON_SRC := $(LIB_DIR)/cjson/cJSON.c
TOML_SRC := $(LIB_DIR)/tomlc17/tomlc17.c
MONOCYPHER_SRC := $(LIB_DIR)/monocypher/monocypher.c
LIB_INCLUDES := -I$(LIB_DIR)/cjson -I$(LIB_DIR)/tomlc17 -I$(LIB_DIR)/monocypher

# Include paths
INCLUDES := -Iinclude -Isrc $(LIB_INCLUDES)

# Version build flags — the banner's compile-time constants, "" where unknown
VERSION_FLAGS := -DDOTTA_BUILD_COMMIT="\"$(GIT_COMMIT)$(GIT_DIRTY)\"" \
                 -DDOTTA_BUILD_BRANCH="\"$(GIT_BRANCH)\"" \
                 -DDOTTA_BUILD_PLATFORM="\"$(CC_MACHINE)\"" \
                 -DDOTTA_BUILD_TYPE="\"$(BUILD_TYPE)\"" \
                 -DDOTTA_BUILD_CC="\"$(CC_VERSION)\""

# Uncrustify config
UNCRUSTIFY_CFG := .uncrustify.cfg

# Directories — the object tree is the build type's
SRC_DIR := src
BUILD_ROOT := build
BUILD_DIR := $(BUILD_ROOT)/$(BUILD_TYPE)
BIN_DIR := bin
ETC_DIR := etc

# Installation directories, staged under DESTDIR by a package build
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
else ifeq ($(BUILD_TYPE),coverage)
TARGET := $(BIN_DIR)/dotta-coverage
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

# Build configuration sentinel: every flag a compile or a link reads, and the
# compiler by version, since $(CC) is a word PATH resolves. Expanded when it
# runs, once the bundled libraries it waits for stand.
BUILD_CONFIG := $(BUILD_DIR)/.build-config
BUILD_STAMP = $(CC_VERSION) $(BUILD_CFLAGS) $(INCLUDES) $(CPPFLAGS) \
              $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) $(CFLAGS) \
              $(LDFLAGS) $(LIBGIT2_LIBS) $(SQLITE3_LIBS)

.PHONY: FORCE
FORCE:

$(BUILD_CONFIG): FORCE | $(BUILD_DIR)
	@NEW='$(subst ','\'',$(BUILD_STAMP))'; \
	 OLD=$$(cat $@ 2>/dev/null || true); \
	 if [ "$$NEW" = "$$OLD" ]; then exit 0; fi; \
	 [ -z "$$OLD" ] || echo "Build config changed — rebuilding all objects"; \
	 printf '%s\n' "$$NEW" > $@

# Version sentinel: the banner's constants change with every commit and with
# the first edit after one.
VERSION_CONFIG := $(BUILD_DIR)/.version-config

$(VERSION_CONFIG): FORCE | $(BUILD_DIR)
	@NEW='$(subst ','\'',$(VERSION_FLAGS))'; \
	 OLD=$$(cat $@ 2>/dev/null || true); \
	 [ "$$NEW" = "$$OLD" ] || printf '%s\n' "$$NEW" > $@

# The libraries: the system's, as pkg-config finds them, or libgit2's and
# SQLite's latest releases built under build/deps. Read below all, so none of
# their rules becomes the default goal. PKG_CONFIG may carry a flag
# (pkg-config --static)
PKG_CONFIG ?= pkg-config
HAVE_PKG_CONFIG := $(shell command -v $(firstword $(PKG_CONFIG)) 2>/dev/null)

# Goals that need no compiler and no libraries
BUILDLESS_GOALS := clean help check-deps format format-all format-check reflow reflow-check uninstall uninstall-completions

ifeq ($(DEPS),system)
# Version floors
LIBGIT2_MIN := 1.9
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
	 if command -v $(firstword $(CC)) >/dev/null 2>&1; then \
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
else
DEPS_DIR := $(BUILD_ROOT)/deps
LIBGIT2_DIR := $(DEPS_DIR)/libgit2
SQLITE3_DIR := $(DEPS_DIR)/sqlite3

# Each archive by its path, so no -L of the user's reaches a system copy. What
# libgit2's .pc names besides is still searched along it first: on macOS, a
# prefix holding GNU libiconv fails the link
LIBGIT2_ARCHIVE := $(LIBGIT2_DIR)/lib/libgit2.a
LIBGIT2_CFLAGS := -I$(LIBGIT2_DIR)/include
LIBGIT2_LIBS = $(patsubst -lgit2,$(LIBGIT2_ARCHIVE),$(shell $(PKG_CONFIG) --static --libs $(LIBGIT2_DIR)/lib/pkgconfig/libgit2.pc))
SQLITE3_ARCHIVE := $(SQLITE3_DIR)/lib/libsqlite3.a
SQLITE3_CFLAGS := -I$(SQLITE3_DIR)/include
SQLITE3_LIBS := $(SQLITE3_ARCHIVE)

# Nothing compiles before both stand
$(BUILD_CONFIG): | $(LIBGIT2_ARCHIVE) $(SQLITE3_ARCHIVE)

# An archive is fetched under a temporary name and dated now: fetch keeps the
# server's date, older than the release file it follows
ifeq ($(BUILD_OS),freebsd)
DOWNLOAD := fetch -q -o
else
DOWNLOAD := curl -fsSL -o
endif

# The newest release of the major dotta is written against
LIBGIT2_MAJOR := 1
LIBGIT2_URL := https://github.com/libgit2/libgit2

# The machine's TLS and its SHA-256, save on Linux: libssl loads there at the
# first HTTPS contact, and its SHA-256 would load it as libgit2 starts
ifeq ($(BUILD_OS),linux)
LIBGIT2_HTTPS := OpenSSL-Dynamic
LIBGIT2_SHA256 := Builtin
else ifeq ($(BUILD_OS),darwin)
LIBGIT2_HTTPS := SecureTransport
LIBGIT2_SHA256 := HTTPS
else
LIBGIT2_HTTPS := OpenSSL
LIBGIT2_SHA256 := HTTPS
endif

# Every option that could link a library the machine may lack is named
LIBGIT2_OPTIONS := -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib \
                   -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=OFF -DBUILD_CLI=OFF \
                   -DUSE_HTTPS=$(LIBGIT2_HTTPS) -DUSE_SHA1=CollisionDetection -DUSE_SHA256=$(LIBGIT2_SHA256) \
                   -DUSE_SSH=OFF -DUSE_BUNDLED_ZLIB=ON -DREGEX_BACKEND=builtin \
                   -DUSE_HTTP_PARSER=builtin -DUSE_NTLMCLIENT=OFF -DUSE_GSSAPI=OFF

$(LIBGIT2_DIR)/release:
	@mkdir -p $(@D)
	@tag=$$(git ls-remote --sort=v:refname --tags --refs $(LIBGIT2_URL) 'v$(LIBGIT2_MAJOR).*' | \
	        sed -n 's|.*refs/tags/\(v$(LIBGIT2_MAJOR)\.[0-9][0-9]*\.[0-9][0-9]*\)$$|\1|p' | tail -n 1); \
	 [ -n "$$tag" ] || { echo "No libgit2 $(LIBGIT2_MAJOR).x release read from $(LIBGIT2_URL)" >&2; exit 1; }; \
	 echo "$$tag" > $@

$(LIBGIT2_DIR)/release.tar.gz: $(LIBGIT2_DIR)/release
	@echo "FETCH $(LIBGIT2_URL)/archive/refs/tags/$$(cat $<).tar.gz"
	@$(DOWNLOAD) $@.part $(LIBGIT2_URL)/archive/refs/tags/$$(cat $<).tar.gz
	@touch $@.part
	@mv $@.part $@

# The libraries serve every build type, so the user's flags and DESTDIR, which
# make exports and CMake reads, are cleared; make -C shares make's job slots
$(LIBGIT2_ARCHIVE): $(LIBGIT2_DIR)/release.tar.gz
	@echo "CMAKE libgit2 $$(cat $(LIBGIT2_DIR)/release) ($(LIBGIT2_DIR)/build.log)"
	@rm -rf $(LIBGIT2_DIR)/src $(LIBGIT2_DIR)/build
	@mkdir -p $(LIBGIT2_DIR)/src
	@tar -xzf $< -C $(LIBGIT2_DIR)/src --strip-components=1
	@CC='$(CC)' CFLAGS= CPPFLAGS= LDFLAGS= cmake -S $(LIBGIT2_DIR)/src -B $(LIBGIT2_DIR)/build -G 'Unix Makefiles' \
	    -DCMAKE_INSTALL_PREFIX=$(CURDIR)/$(LIBGIT2_DIR) $(LIBGIT2_OPTIONS) > $(LIBGIT2_DIR)/build.log 2>&1 \
	    || { tail -n 30 $(LIBGIT2_DIR)/build.log; exit 1; }
	@$(MAKE) -C $(LIBGIT2_DIR)/build >> $(LIBGIT2_DIR)/build.log 2>&1 \
	    || { tail -n 30 $(LIBGIT2_DIR)/build.log; exit 1; }
	@DESTDIR= cmake --install $(LIBGIT2_DIR)/build >> $(LIBGIT2_DIR)/build.log 2>&1 \
	    || { tail -n 30 $(LIBGIT2_DIR)/build.log; exit 1; }

# SQLite's recommended options for one thread and no extension
# (sqlite.org/compile.html)
SQLITE3_URL := https://sqlite.org
SQLITE3_OPTIONS := -DSQLITE_DQS=0 -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 \
                   -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_OMIT_DECLTYPE -DSQLITE_OMIT_DEPRECATED \
                   -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_SHARED_CACHE \
                   -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_USE_ALLOCA

$(SQLITE3_DIR)/release:
	@mkdir -p $(@D)
	@path=$$($(DOWNLOAD) - $(SQLITE3_URL)/download.html | \
	         sed -n 's|^PRODUCT,[^,]*,\([^,]*/sqlite-autoconf-[0-9]*\.tar\.gz\),.*|\1|p' | head -n 1); \
	 [ -n "$$path" ] || { echo "No SQLite release read from $(SQLITE3_URL)/download.html" >&2; exit 1; }; \
	 echo "$$path" > $@

$(SQLITE3_DIR)/release.tar.gz: $(SQLITE3_DIR)/release
	@echo "FETCH $(SQLITE3_URL)/$$(cat $<)"
	@$(DOWNLOAD) $@.part $(SQLITE3_URL)/$$(cat $<)
	@touch $@.part
	@mv $@.part $@

$(SQLITE3_ARCHIVE): $(SQLITE3_DIR)/release.tar.gz
	@rm -rf $(SQLITE3_DIR)/src
	@mkdir -p $(SQLITE3_DIR)/src $(SQLITE3_DIR)/include $(@D)
	@tar -xzf $< -C $(SQLITE3_DIR)/src --strip-components=1
	@echo "CC $(SQLITE3_DIR)/src/sqlite3.c"
	@$(CC) -O2 $(SQLITE3_OPTIONS) -c $(SQLITE3_DIR)/src/sqlite3.c -o $(SQLITE3_DIR)/sqlite3.o
	@cp $(SQLITE3_DIR)/src/sqlite3.h $(SQLITE3_DIR)/include/
	@echo "AR $@"
	@rm -f $@
	@$(AR) rcs $@ $(SQLITE3_DIR)/sqlite3.o

# Package-manager hint
ifeq ($(BUILD_OS),darwin)
define INSTALL_HINT
  brew install pkg-config cmake
endef
else ifeq ($(BUILD_OS),freebsd)
define INSTALL_HINT
  pkg install pkgconf cmake-core git
endef
else
define INSTALL_HINT
  Debian:    sudo apt install pkg-config cmake git curl
  Fedora:    sudo dnf install pkgconf-pkg-config cmake git curl
  Arch:      sudo pacman -S pkgconf cmake git curl
endef
endif
export INSTALL_HINT

# Fail at the point of misconfiguration
ifneq ($(filter-out $(BUILDLESS_GOALS),$(or $(MAKECMDGOALS),all)),)
ifeq ($(HAVE_PKG_CONFIG),)
$(error pkg-config not found — install it, then run 'make check-deps DEPS=bundled')
endif
endif

# Check dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies (DEPS=bundled)..."
	@fail=0; \
	 if [ -n "$(HAVE_PKG_CONFIG)" ]; then \
	   printf '  %-12s %s\n' "pkg-config" "$(HAVE_PKG_CONFIG)"; \
	 else \
	   printf '  %-12s %s\n' "pkg-config" "NOT FOUND (required to link libgit2)"; \
	   fail=1; \
	 fi; \
	 if command -v $(firstword $(CC)) >/dev/null 2>&1; then \
	   printf '  %-12s %s\n' "$(CC)" "$$($(CC) --version | head -n1)"; \
	 else \
	   printf '  %-12s %s\n' "$(CC)" "NOT FOUND"; \
	   fail=1; \
	 fi; \
	 for program in cmake git tar $(firstword $(DOWNLOAD)); do \
	   if found=$$(command -v $$program); then \
	     printf '  %-12s %s\n' "$$program" "$$found"; \
	   else \
	     printf '  %-12s %s\n' "$$program" "NOT FOUND"; \
	     fail=1; \
	   fi; \
	 done; \
	 echo ""; \
	 if [ $$fail -ne 0 ]; then \
	   echo "Missing dependencies. Install with:"; \
	   printf '%s\n' "$$INSTALL_HINT"; \
	   exit 1; \
	 fi; \
	 echo "All dependencies satisfied."
endif

# Header dependencies
DEPFLAGS = -MMD -MP

# Compile source files: dotta's headers, then the user's, then the libraries'
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(BUILD_CONFIG) | $(BUILD_LAYER_DIRS)
	@echo "CC $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(INCLUDES) $(CPPFLAGS) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) \
	    $(CFLAGS) -c $< -o $@

# The banner renderer: the one translation unit that reads VERSION_FLAGS, so
# the one that carries them and follows the version sentinel.
$(BUILD_DIR)/utils/version.o: $(SRC_DIR)/utils/version.c $(BUILD_CONFIG) $(VERSION_CONFIG) | $(BUILD_LAYER_DIRS)
	@echo "CC $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(INCLUDES) $(CPPFLAGS) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) \
	    $(CFLAGS) $(VERSION_FLAGS) -c $< -o $@

# Compile vendor files
$(BUILD_DIR)/lib/cJSON.o: $(CJSON_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lib/tomlc17.o: $(TOML_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lib/monocypher.o: $(MONOCYPHER_SRC) $(BUILD_CONFIG) | $(BUILD_DIR)/lib
	@echo "CC $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(LIB_INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Link main executable
$(TARGET): $(LIB_OBJ) $(MAIN_OBJ) | $(BIN_DIR)
	@echo "LD $@ ($(BUILD_TYPE))"
	@$(CC) $(BUILD_CFLAGS) $(CFLAGS) $(LDFLAGS) $^ $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -pthread -o $@

# Debug build
.PHONY: debug
debug: all

# The library — every object but main's — archived for the unit binaries
LIBDOTTA := $(BUILD_DIR)/libdotta.a

$(LIBDOTTA): $(LIB_OBJ)
	@echo "AR $@"
	@rm -f $@
	@$(AR) rcs $@ $^

# Tests — the unit binaries live in the build type's tree beside the objects
# they were linked from; under BUILD_TYPE=debug they are sanitizer binaries,
# the runtime coming in through the same flags on the link. They link with
# -pthread, as the binary does, which the key derivation's threads need
# (crypto/kdf.c), as does a suite that runs an ask on a stack of its own
# (tests/test-source.c stack_used), and a platform with its threads outside libc
# (FreeBSD's libthr) needs said.
TESTS_DIR := tests
TESTS_BIN_DIR := $(BUILD_DIR)/tests
TESTS_SRC := $(wildcard $(TESTS_DIR)/test-*.c)
TESTS_BIN := $(patsubst $(TESTS_DIR)/%.c,$(TESTS_BIN_DIR)/%,$(TESTS_SRC))

$(TESTS_BIN_DIR):
	@mkdir -p $@

$(TESTS_BIN_DIR)/%: $(TESTS_DIR)/%.c $(LIBDOTTA) | $(TESTS_BIN_DIR)
	@echo "CC TEST $<"
	@$(CC) $(BUILD_CFLAGS) $(DEPFLAGS) $(INCLUDES) $(CPPFLAGS) $(LIBGIT2_CFLAGS) $(SQLITE3_CFLAGS) \
	    $(CFLAGS) $(LDFLAGS) $< $(LIBDOTTA) $(LIBGIT2_LIBS) $(SQLITE3_LIBS) -pthread -o $@

# Suites are independent; run this many at a time (JOBS=1 keeps start order)
JOBS ?= 8

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

# Coverage — which lines of src/ the suites run.
COVERAGE_DIR := $(BUILD_DIR)/profile
COVERAGE_RAW := $(COVERAGE_DIR)/raw
COVERAGE_DATA := $(COVERAGE_DIR)/dotta.profdata

LLVM_PROFDATA := $(shell $(CC) -print-prog-name=llvm-profdata 2>/dev/null)
ifeq ($(filter /%,$(LLVM_PROFDATA)),)
LLVM_PROFDATA := llvm-profdata
endif
LLVM_COV := $(shell $(CC) -print-prog-name=llvm-cov 2>/dev/null)
ifeq ($(filter /%,$(LLVM_COV)),)
LLVM_COV := llvm-cov
endif

# The suites' exit status is the target's, so a failing run still reports.
.PHONY: coverage
coverage: $(TESTS_BIN) $(TARGET)
	@rm -rf $(COVERAGE_RAW) $(COVERAGE_DATA)
	@mkdir -p $(COVERAGE_RAW)
	@LLVM_PROFILE_FILE=$(CURDIR)/$(COVERAGE_RAW)/%m.profraw $(RUN_SUITES) $(SUITE); \
	 suites=$$?; $(MAKE) --no-print-directory coverage-report; exit $$suites

# Re-render the last run's profile without re-running the suites.
.PHONY: coverage-report
coverage-report:
	@ls $(COVERAGE_RAW)/*.profraw > /dev/null 2>&1 || \
	    { echo "no profile in $(COVERAGE_RAW) — run 'make coverage' first"; exit 2; }
	@$(LLVM_PROFDATA) merge -sparse $(COVERAGE_RAW)/*.profraw -o $(COVERAGE_DATA)
	@echo ""
	@$(LLVM_COV) report $(TARGET) $(addprefix -object ,$(TESTS_BIN)) \
	    -instr-profile=$(COVERAGE_DATA) $(SRC_DIR)
	@echo ""
	@echo "one file: $(LLVM_COV) show $(TARGET) -instr-profile=$(COVERAGE_DATA) src/cmds/diff.c"

# Clean build artifacts — both build types
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_ROOT) $(BIN_DIR)

# Install
.PHONY: install
install: $(TARGET)
	@echo "Installing binary..."
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/dotta
	@echo "  Installed: $(DESTDIR)$(BINDIR)/dotta"
	@echo ""
	@echo "Installing configuration examples..."
	@install -d $(DESTDIR)$(DATADIR)
	@install -m 644 $(ETC_DIR)/config.example.toml $(DESTDIR)$(DATADIR)/config.example.toml
	@echo "  Installed: $(DESTDIR)$(DATADIR)/config.example.toml"
	@echo ""
	@echo "Installing hook samples..."
	@install -d $(DESTDIR)$(DATADIR)/hooks
	@for f in $(ETC_DIR)/hooks/*.sample; do \
		install -m 755 "$$f" "$(DESTDIR)$(DATADIR)/hooks/$$(basename "$$f")"; \
	done
	@install -m 644 $(ETC_DIR)/hooks/README.md $(DESTDIR)$(DATADIR)/hooks/README.md
	@echo "  Installed: $(DESTDIR)$(DATADIR)/hooks/*.sample"
	@echo "  Installed: $(DESTDIR)$(DATADIR)/hooks/README.md"
	@echo ""

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling dotta..."
	@rm -f $(DESTDIR)$(BINDIR)/dotta
	@echo "  Removed: $(DESTDIR)$(BINDIR)/dotta"
	@rm -rf $(DESTDIR)$(DATADIR)
	@echo "  Removed: $(DESTDIR)$(DATADIR)"
	@rm -f $(DESTDIR)$(FISHDIR)/dotta.fish
	@echo "  Removed: $(DESTDIR)$(FISHDIR)/dotta.fish"
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
	@if [ -d "$(DESTDIR)$(FISHDIR)" ] || [ ! -e "$(DESTDIR)$(FISHDIR)" ]; then \
		install -d "$(DESTDIR)$(FISHDIR)" && \
		install -m 644 $(COMPLETIONS_GEN) "$(DESTDIR)$(FISHDIR)/dotta.fish" && \
		echo "  Installed: $(DESTDIR)$(FISHDIR)/dotta.fish"; \
	else \
		echo "  Skipped fish completions ($(DESTDIR)$(FISHDIR) exists but is not a directory)"; \
	fi

# Uninstall shell completions
.PHONY: uninstall-completions
uninstall-completions:
	@echo "Removing shell completions..."
	@rm -f "$(DESTDIR)$(FISHDIR)/dotta.fish"
	@echo "  Removed: $(DESTDIR)$(FISHDIR)/dotta.fish"

# Install all (binary + completions)
.PHONY: install-all
install-all: install
	@$(MAKE) --no-print-directory install-completions

# Where the C sources live — a find expression and an unglobbed git pathspec
SRC_ROOTS := src include
FORMAT_FIND := $(SRC_ROOTS) \( -name "*.c" -o -name "*.h" \)
SRC_PATHSPEC := $(foreach r,$(SRC_ROOTS),'$(r)/*.c' '$(r)/*.h')

# What this tree changed, tracked or not. Override with CHANGED_SRC="src/a.c".
CHANGED_SRC ?= $(shell git diff --name-only --diff-filter=d HEAD -- $(SRC_PATHSPEC); \
                       git ls-files --others --exclude-standard -- $(SRC_PATHSPEC))

# Format what changed (requires uncrustify)
.PHONY: format
format:
	@files='$(CHANGED_SRC)'; \
	if [ -z "$$files" ]; then \
	  echo "No modified .c/.h files to format."; \
	else \
	  echo "Formatting $$(echo $$files | wc -w | tr -d ' ') file(s)..."; \
	  uncrustify -c $(UNCRUSTIFY_CFG) -l C --no-backup -q $$files; \
	fi

# Format the whole tree — the sweep after a config edit or a version bump
.PHONY: format-all
format-all:
	@echo "Formatting the tree..."
	@find $(FORMAT_FIND) -print0 | xargs -0 uncrustify -c $(UNCRUSTIFY_CFG) -l C --no-backup -q

# Check formatting without modifying files — tree-wide, where drift shows
.PHONY: format-check
format-check:
	@find $(FORMAT_FIND) -print0 | xargs -0 uncrustify -c $(UNCRUSTIFY_CFG) -l C --check -q \
	  || { echo "Formatting issues found. Run 'make format-all' to fix."; exit 1; }
	@echo "All files formatted correctly."

# Reflow block comments (requires python3). Runs after uncrustify
REFLOW := scripts/reflow_comments.py
REFLOW_WIDTH ?= 80
REFLOW_SLACK ?= 4

.PHONY: reflow
reflow:
	@command -v python3 >/dev/null 2>&1 || \
	  { echo "Error: python3 not installed."; exit 1; }
	@files='$(CHANGED_SRC)'; \
	if [ -z "$$files" ]; then \
	  echo "No modified .c/.h files to reflow."; \
	else \
	  echo "Reflowing comments..."; \
	  python3 $(REFLOW) --width $(REFLOW_WIDTH) --slack $(REFLOW_SLACK) --apply $$files; \
	fi

# Show what reflow would change without writing; non-zero if anything would
.PHONY: reflow-check
reflow-check:
	@files='$(CHANGED_SRC)'; \
	if [ -n "$$files" ]; then \
	  python3 $(REFLOW) --width $(REFLOW_WIDTH) --slack $(REFLOW_SLACK) $$files \
	    || { echo "Comment reflow pending. Run 'make reflow' to fix."; exit 1; }; \
	fi
	@echo "All comments reflowed correctly."

# Static analysis with clang-tidy (requires compile_commands.json), over this
# tree's src/ alone
TIDY ?= clang-tidy
RUN_TIDY ?= run-clang-tidy
TIDY_JOBS ?= $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
TIDY_FILTER ?= ^$(CURDIR)/src/.*\.c$$
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

# Regenerate compile_commands.json via bear; a suite with no entry is guessed
.PHONY: compile-commands
compile-commands:
	@command -v bear >/dev/null 2>&1 || \
		{ echo "Error: 'bear' not installed. Install via: brew install bear"; exit 1; }
	@$(MAKE) clean
	@bear -- $(MAKE) -j$$(sysctl -n hw.ncpu 2>/dev/null || nproc) all $(TESTS_BIN)

# Help
.PHONY: help
help:
	@echo "dotta Makefile targets:"
	@echo "  all                   - Build main executable (default): bin/dotta"
	@echo "  debug                 - Build with debug symbols and sanitizers: bin/dotta-debug"
	@echo "  test                  - Build and run unit tests"
	@echo "  test-cli              - Run CLI suites (SUITE=\"ghosts export\" to filter, JOBS=1 for start order)"
	@echo "  test-all              - Run unit tests and CLI suites"
	@echo "  coverage              - Run the suites instrumented and report line coverage of src/"
	@echo "  coverage-report       - Re-render the last coverage run without re-running it"
	@echo "  clean                 - Remove build artifacts (both build types)"
	@echo "  completions           - Generate the fish completion script from the binary"
	@echo "  install               - Install binary, configs, and hooks to $(DESTDIR)$(PREFIX)"
	@echo "  install-completions   - Install fish shell completions"
	@echo "  install-all           - Install binary, configs, hooks, and completions"
	@echo "  uninstall             - Remove installed files from $(DESTDIR)$(PREFIX)"
	@echo "  uninstall-completions - Remove shell completions only"
	@echo "  format                - Format the git-modified .c/.h files with uncrustify"
	@echo "  format-all            - Format every .c/.h file in the tree"
	@echo "  format-check          - Check formatting of the whole tree without modifying files"
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
	@echo "so 'make debug test-all' runs the suites under ASan/UBSan; 'coverage' likewise."
	@echo "Each type has its own tree (build/<type>/) and binary, so the three coexist."
	@echo ""
	@echo "Dependencies: DEPS=bundled builds libgit2's and SQLite's latest releases in"
	@echo "build/deps and links them in, where the system's are missing or too old. It"
	@echo "needs cmake, git, curl or fetch, and the network; 'make check-deps DEPS=bundled'"
	@echo "says which are missing, and 'make clean' takes the libraries with the rest."
	@echo ""
	@echo "Installation paths:"
	@echo "  Binary:       $(DESTDIR)$(BINDIR)/dotta"
	@echo "  Configs:      $(DESTDIR)$(DATADIR)/"
	@echo "  Hooks:        $(DESTDIR)$(DATADIR)/hooks/"
	@echo "  Completions:  $(DESTDIR)$(FISHDIR)/dotta.fish"
	@echo ""
	@echo "PREFIX moves the install, and DESTDIR stages it for a package:"
	@echo "  make install PREFIX=/usr DESTDIR=/tmp/pkg"
	@echo "CC picks the compiler; CPPFLAGS, CFLAGS and LDFLAGS add to the build's own"
	@echo "flags, so CFLAGS=-Wno-error lets a build finish past a compiler's warning."

# Dependency tracking
-include $(LIB_OBJ:.o=.d)
-include $(MAIN_OBJ:.o=.d)
-include $(TESTS_BIN:=.d)
