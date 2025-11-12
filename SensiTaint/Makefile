# Makefile for sensitaint

# Compiler
CXX = g++

# Path to LLVM build/install
LLVM_PREFIX ?= $(HOME)/cs263/CS263-FinalProject/lib/llvm/install
LLVM_CONFIG = $(LLVM_PREFIX)/bin/llvm-config

# Source files
SRC = $(wildcard *.cc)
TARGET = sensitaint

# Compiler flags from LLVM
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter $(shell $(LLVM_CONFIG) --cppflags)
LDFLAGS  = $(shell $(LLVM_CONFIG) --ldflags)
LIBS     = $(shell $(LLVM_CONFIG) --libs core irreader bitwriter) $(shell $(LLVM_CONFIG) --system-libs)

# Default target
all: $(TARGET)

# Build sensitaint
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LIBS)

# Clean
clean:
	rm -f $(TARGET)

.PHONY: all clean install-llvm
