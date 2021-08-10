# Makefile
# rules (always with .out)
# SRC-X.out += abc        # extra source: abc.c
# MOD-X.out += abc        # extra module: abc.c abc.h
# ASM-X.out += abc        # extra assembly: abc.S
# DEP-X.out += abc        # extra dependency: abc
# FLG-X.out += -finline   # extra flags
# LIB-X.out += abc        # extra -labc options

# X.out : xyz.h xyz.c # for extra dependences that are to be compiled/linked.

VPATH += .:c/

# X => X.out
TARGETS += test_qcc
# X => X.c only
SOURCES +=
# X => X.S only
ASSMBLY +=
# X => X.c X.h
MODULES += c/lib
# X => X.h
HEADERS +=

MOD-test_qcc.out += qcc

# EXTERNSRC/EXTERNDEP do not belong to this repo.
# extern-src will be linked
EXTERNSRC +=
# extern-dep will not be linked
EXTERNDEP +=

FLG +=
LIB += rt m uring

# when $ make FORKER_PAPI=y
ifeq ($(strip $(FORKER_PAPI)),y)
LIB += papi
FLG += -DFORKER_PAPI
endif

include c/Makefile.common
