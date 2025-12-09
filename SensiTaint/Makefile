# Makefile for sensitaint

# Compiler
CXX = g++

# Path to LLVM build/install
LLVM_CONFIG = $(shell which llvm-config)

# Source files
SRC = $(wildcard *.cc)
TARGET = sensitaint

# Compiler flags from LLVM
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter \
           $(shell $(LLVM_CONFIG) --cppflags) \
           -I/usr/local/include -I/usr/local/include/wise_enum

# Linker flags from LLVM
LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags) -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu

# Libraries: PhASAR -> Boost -> LLVM
LIBS = \
    -lphasar_phasarllvm_utils -lphasar_controlflow -lphasar_pointer \
    -lphasar_db -lphasar_utils -lphasar_config -lphasar_ifdside \
    -lboost_log -lboost_log_setup -lboost_thread -lboost_system \
    -lboost_filesystem -lboost_program_options -lboost_date_time -lpthread \
    $(shell $(LLVM_CONFIG) --libs all) \
    $(shell $(LLVM_CONFIG) --system-libs)

# Default target
all: $(TARGET)

# Build sensitaint
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LIBS)

# Clean
clean:
	rm -f $(TARGET)

# Docker targets
docker-run:
	docker run \
		--cap-add=SYS_PTRACE --security-opt seccomp=unconfined\
		-it --rm \
		--ulimit core=-1 \
		--security-opt seccomp=unconfined \
		--entrypoint /bin/bash \
		-v $(PWD)/..:/workspace \
		-w /workspace/SensiTaint \
		pdschbrt/phasar

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
	python ../test_dir/scan_core.py core $(BYTES)

.PHONY: all clean docker-build docker-run test
