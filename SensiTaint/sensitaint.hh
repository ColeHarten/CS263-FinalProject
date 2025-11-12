#ifndef SENSITAINT_HH
#define SENSITAINT_HH
#include <stdio.h>
#include <string>
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instruction.h"

// ANSI color codes
namespace Colors {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

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

