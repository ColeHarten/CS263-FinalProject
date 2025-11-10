# Simple Makefile for compiling a C file and showing LLVM IR

CC := clang
CFLAGS := -Wall -Wextra -O2
LDFLAGS :=

# Default target: compile the file passed as 'make FILE=source.c'
all:
	@if [ -z "$(FILE)" ]; then \
		echo "Usage: make FILE=<source.c>"; \
		exit 1; \
	fi
	@echo "[1/3] Generating LLVM IR..."
	$(CC) $(CFLAGS) -S -emit-llvm $(FILE) -o $(basename $(FILE)).ll

	@echo "[2/3] Displaying LLVM IR:"
	@echo "----------------------------------------"
	@cat $(basename $(FILE)).ll | head -n 40
	@echo "----------------------------------------"

	@echo "[3/3] Compiling to binary..."
	$(CC) $(CFLAGS) $(FILE) -o $(basename $(FILE)) $(LDFLAGS)

# Clean built artifacts
clean:
	rm -f *.o *.out *.exe *.a *.so *.ll
	rm -f $(basename $(FILE))
