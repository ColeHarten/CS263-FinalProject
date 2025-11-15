# Makefile for sensitaint

# Compiler
CXX = g++

# Path to LLVM build/install
LLVM_PREFIX ?= /usr
LLVM_CONFIG = $(shell which llvm-config-18 || which llvm-config)

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

# Docker targets
docker-build:
	docker build -t sensitaint .

docker-run:
	docker run -it --rm \
		--ulimit core=-1 \
		--security-opt seccomp=unconfined \
		-v $(PWD)/..:/home/dev/CS263-FinalProject \
		-w /home/dev/CS263-FinalProject/SensiTaint \
		sensitaint

.PHONY: all clean docker-build docker-run
