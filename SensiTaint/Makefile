# Makefile for sensitaint

# Compiler
CXX = g++

# Path to LLVM build/install
LLVM_PREFIX ?= /usr
LLVM_CONFIG = $(shell which llvm-config || echo /opt/homebrew/opt/llvm@15/bin/llvm-config)

# Source files
SRC = $(wildcard *.cc)
TARGET = sensitaint

# Compiler flags from LLVM
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter $(shell $(LLVM_CONFIG) --cppflags)
LDFLAGS  = $(shell $(LLVM_CONFIG) --ldflags)
LIBS     = $(shell $(LLVM_CONFIG) --libs core irreader bitwriter analysis) $(shell $(LLVM_CONFIG) --system-libs)

PHASAR_ROOT ?= /opt/phasar/install
PHASAR_DEPS_LIBDIR ?= $(PHASAR_ROOT)/lib/phasar/deps/lib

CXXFLAGS += -I$(PHASAR_ROOT)/include
LDFLAGS  += -L$(PHASAR_ROOT)/lib -L$(PHASAR_DEPS_LIBDIR)

# PhASAR and its component libs
CXXFLAGS += -DPHASAR_ENABLED -I/usr/local/include -I/opt/homebrew/include
LIBS += -L/usr/local/lib \
	-Wl,--whole-archive \
	-lphasar_llvm_dataflow \
  	-lphasar_llvm_domain \
	-lphasar_llvm_ifdside \
	-lphasar_llvm_db \
	-lphasar_llvm_controlflow \
	-lphasar_llvm_pointer \
	-lphasar_llvm_typehierarchy \
	-lphasar_llvm_utils \
	-lphasar_llvm_mono \
	-lphasar_llvm \
	-lphasar_controlflow \
	-lphasar_taintconfig \
	-lphasar_dataflow \
	-lphasar_domain \
	-lphasar_utils \
	-lphasar_config \
	-lphasar_pass \
	-lphasar \
	-Wl,--no-whole-archive \
	-lnlohmann_json_schema_validator

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
