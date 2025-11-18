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

# Test target - usage: make test BYTES=0xbeeffeed
test:
	@if [ -z "$(BYTES)" ]; then \
		echo "Usage: make test BYTES=<hex_value>"; \
		echo "Example: make test BYTES=0xbeeffeed"; \
		exit 1; \
	fi
	@echo "Running test with bytes: $(BYTES)"
	@echo "Cleaning and building..."
	$(MAKE) clean
	$(MAKE)
	@echo "Running sensitaint on test.c..."
	./sensitaint ../test_dir/test.c test
	@echo "Executing instrumented test binary..."
	./test || true
	@echo "Scanning core dump for bytes: $(BYTES)"
	python3 ../test_dir/scan_core.py core $(BYTES)

.PHONY: all clean docker-build docker-run test
