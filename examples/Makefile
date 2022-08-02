DEBUG = 0
# SANITIZER =
# OLEVEL =

# ----------

BUILDDIR = build
EXAMPLES = encrypt_with_bear

# ----------

MAKE    = make
CC      = gcc
OPTS    =
LDFLAGS =
COMMON  = -I../third_party/bearssl/inc -I../include
STD     = -std=c99
LIBS    = ../third_party/bearssl/build/libbearssl.a

# ----------

override BUILDDIRPATH  = $(addsuffix /, $(addprefix ./, $(BUILDDIR)))
override EXAMPLESPATHS = $(addprefix $(addsuffix /, $(BUILDDIR)), $(EXAMPLES))

# ----------

OLEVELDEFAULT = Ofast

CFLAGS = $(STD) -Wall -Wextra -pedantic
ifeq ($(DEBUG), 1)
	OPTS = -g -ggdb -DDERDEC_DEBUG=1

	override OLEVELDEFAULT = O0

	ifndef SANITIZER
		SANITIZER = address undefined
	endif
endif

ifdef SANITIZER
	ifneq (,$(findstring address,$(SANITIZER)))
		CFLAGS  += -fsanitize=address
		LDFLAGS += -fsanitize=address
	endif
	ifneq (,$(findstring undefined,$(SANITIZER)))
		CFLAGS  += -fsanitize=undefined
		LDFLAGS += -fsanitize=undefined
	endif
endif

ifndef NOCOLORS
	COMMON += -fdiagnostics-color=always
endif

ifndef OLEVEL
	OLEVEL = $(OLEVELDEFAULT)
endif
OPTS += $(addprefix -, $(OLEVEL))

ifdef NOCOLORS
	OPTS += -DDERDEC_DEBUG_NOCOLORS=1
endif

CFLAGS  += $(OPTS)
LDFLAGS += $(LIBS)

# ----------

.PHONY: all
all: $(BUILDDIRPATH) $(EXAMPLESPATHS)
	@printf '\n'

$(LIBS):
	$(error '$@' dependency is missing! Did you forget to build it?)

$(BUILDDIRPATH):
	@printf ' > '
	mkdir -p $(BUILDDIR)
	@printf '\n'

$(EXAMPLESPATHS): $(LIBS)
	@printf ' > '
	$(CC) $(COMMON) $(CFLAGS) $(notdir $(addsuffix .c, $@)) -o $@ $(LDFLAGS)
	@printf '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'

.PHONY: clean
clean:
	@printf ' > '
	rm -rf $(BUILDDIRPATH)/*
	@printf '\n'
