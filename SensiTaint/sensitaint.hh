#ifndef SENSITAINT_HH
#define SENSITAINT_HH
#include <stdio.h>
#include <string>
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instruction.h"

#define FATAL(...) \
    do { \
        fprintf(stderr, "FATAL: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

// Struct for tracking sensitive variables
struct SensitiveVar {
    llvm::Value* variable;
    std::string name;
    llvm::Instruction* location;
    bool isGlobal;
};

void register_sensitive(void *ptr, size_t sz);
void erase_sensitive();

#endif

